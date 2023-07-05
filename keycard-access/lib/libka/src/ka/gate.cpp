//
// Created by spak on 10/1/22.
//

#include <desfire/esp32/utils.hpp>
#include <ka/desfire_fs.hpp>
#include <ka/gate.hpp>
#include <ka/member_token.hpp>
#include <ka/nvs.hpp>
#include <mlab/strutils.hpp>
#include <pn532/controller.hpp>
#include <sdkconfig.h>
#include <sodium/crypto_kdf_blake2b.h>
#include <sodium/randombytes.h>


using namespace std::chrono_literals;

namespace ka {

    namespace {
        constexpr auto ka_namespc = "keycard-access";
        constexpr auto ka_sk = "secret-key";
        constexpr auto ka_desc = "description";
        constexpr auto ka_gid = "gate-id";
        constexpr auto ka_prog_pk = "programmer-key";
        constexpr auto ka_base_key = "gate-base-key";


#ifdef CONFIG_NVS_ENCRYPTION
        constexpr bool nvs_encrypted = true;
#else
        constexpr bool nvs_encrypted = false;
#endif
        constexpr std::array<char, crypto_kdf_blake2b_CONTEXTBYTES> app_master_key_context{"gateapp"};
    }// namespace

    static_assert(gate_base_key::array_size == crypto_kdf_blake2b_KEYBYTES);

    gate_token_key gate_base_key::derive_token_key(const token_id &token_id, std::uint8_t key_no) const {
        desfire::key_body<key_type::size> derived_key_data{};
        if (0 != crypto_kdf_blake2b_derive_from_key(
                         derived_key_data.data(), derived_key_data.size(),
                         pack_token_id(token_id),
                         app_master_key_context.data(),
                         data())) {
            ESP_LOGE("KA", "Unable to derive root key.");
        }
        return gate_token_key{key_no, derived_key_data};
    }

    void gate::try_authenticate(member_token &token, gate_auth_responder &responder) const {
        if (const auto r = token.read_encrypted_gate_file(*this, true, true); r) {
            ESP_LOGI("KA", "Authenticated as %s.", r->first.holder.c_str());
            responder.on_authentication_success(r->first);
        } else {
            switch (r.error()) {
                case desfire::error::app_not_found:
                    [[fallthrough]];
                case desfire::error::file_not_found:
                    ESP_LOGI("KA", "Not enrolled.");
                    break;
                case desfire::error::app_integrity_error:
                    [[fallthrough]];
                case desfire::error::crypto_error:
                    [[fallthrough]];
                case desfire::error::malformed:
                    [[fallthrough]];
                case desfire::error::file_integrity_error:
                    ESP_LOGW("KA", "Unable to authenticate, %s", member_token::describe(r.error()));
                    responder.on_authentication_fail(r.error(), true);
                    break;
                default:
                    ESP_LOGW("KA", "Unable to authenticate, %s", member_token::describe(r.error()));
                    responder.on_authentication_fail(r.error(), false);
                    break;
            }
        }
    }

    pn532::post_interaction gate_responder::interact_with_token(member_token &token) {
        if (_g.is_configured()) {
            _g.try_authenticate(token, *this);
        }
        return pn532::post_interaction::reject;
    }

    void gate_responder::on_authentication_success(identity const &id) {
        const auto s_id = mlab::data_to_hex_string(id.id);
        ESP_LOGI("GATE", "Authenticated as %s via %s.", id.holder.c_str(), s_id.c_str());
    }
    void gate_responder::on_authentication_fail(desfire::error auth_error, bool might_be_tampering) {
        ESP_LOGE("GATE", "Authentication failed: %s%s.",
                 member_token::describe(auth_error), (might_be_tampering ? " (might be tampering)." : "."));
    }
    void gate_responder::on_activation(pn532::scanner &, pn532::scanned_target const &target) {
        const auto s_id = mlab::data_to_hex_string(target.nfcid);
        ESP_LOGI("GATE", "Activated NFC target %s", s_id.c_str());
    }
    void gate_responder::on_release(pn532::scanner &, pn532::scanned_target const &target) {
        const auto s_id = mlab::data_to_hex_string(target.nfcid);
        ESP_LOGI("GATE", "Released NFC target %s", s_id.c_str());
    }
    void gate_responder::on_leaving_rf(pn532::scanner &, pn532::scanned_target const &target) {
        const auto s_id = mlab::data_to_hex_string(target.nfcid);
        ESP_LOGI("GATE", "NFC target %s has left the RF field.", s_id.c_str());
    }
    void gate_responder::on_failed_scan(pn532::scanner &, pn532::channel_error err) {
        ESP_LOGV("GATE", "Scan failed with error: %s", pn532::to_string(err));
    }

    void gate::log_public_gate_info() const {
        ESP_LOGI("KA", "Gate %lu", std::uint32_t(this->id()));
        ESP_LOGI("KA", "Gate public key:");
        ESP_LOG_BUFFER_HEX_LEVEL("KA", keys().raw_pk().data(), keys().raw_pk().size(), ESP_LOG_INFO);
        ESP_LOGI("KA", "Keymaker public key:");
        ESP_LOG_BUFFER_HEX_LEVEL("KA", keymaker_pk().raw_pk().data(), keymaker_pk().raw_pk().size(), ESP_LOG_INFO);
    }

    bool gate::is_configured() const {
        return _id != std::numeric_limits<gate_id>::max();
    }
    pub_key const &gate::keymaker_pk() const {
        return _km_pk;
    }
    gate_id gate::id() const {
        return _id;
    }

    gate_base_key const &gate::app_base_key() const {
        return _base_key;
    }

    gate::gate() : device{},
                   _id{std::numeric_limits<gate_id>::max()},
                   _km_pk{},
                   _base_key{},
                   _gate_ns{nullptr} {
        if (storage() != nullptr) {
            _gate_ns = storage()->open_namespc("ka-gate");
            if (_gate_ns) {
                if (const auto r = _gate_ns->get_u32("id"); r) {
                    _id = gate_id{*r};
                }
                if (const auto r = _gate_ns->get_blob("keymaker-pubkey"); r) {
                    _km_pk = pub_key{r->data_view()};
                } else {
                    // Reset
                    _id = std::numeric_limits<gate_id>::max();
                    return;
                }
                if (const auto r = _gate_ns->get_blob("base-key"); r and r->size() == gate_base_key::array_size) {
                    std::copy_n(std::begin(*r), gate_base_key::array_size, std::begin(_base_key));
                } else {
                    // Reset
                    _id = std::numeric_limits<gate_id>::max();
                    _km_pk = {};
                }
            }
        }
    }

    void gate::reset() {
        ESP_LOGW("KA", "Gate is being reset.");
        _id = std::numeric_limits<gate_id>::max();
        _km_pk = {};
        _base_key = {};
        if (_gate_ns) {
            _gate_ns->erase("id");
            _gate_ns->erase("keymaker-pubkey");
            _gate_ns->erase("base-key");
            _gate_ns->commit();
        }
    }


    std::optional<gate_base_key> gate::configure(gate_id gid, pub_key keymaker_pubkey) {
        if (is_configured()) {
            ESP_LOGE("KA", "Attempt to reconfigure gate %lu as gate %lu with the following public key:",
                     std::uint32_t(id()), std::uint32_t(gid));
            ESP_LOG_BUFFER_HEX_LEVEL("KA", keymaker_pubkey.raw_pk().data(), keymaker_pubkey.raw_pk().size(), ESP_LOG_ERROR);
            return std::nullopt;
        }
        ESP_LOGI("KA", "Configuring as gate %lu, with the following keymaker pubkey:", std::uint32_t(gid));
        ESP_LOG_BUFFER_HEX_LEVEL("KA", keymaker_pubkey.raw_pk().data(), keymaker_pubkey.raw_pk().size(), ESP_LOG_INFO);
        _id = gid;
        _km_pk = keymaker_pubkey;
        // Generate a new app base key
        randombytes_buf(_base_key.data(), _base_key.size());

        if (_gate_ns) {
#ifndef CONFIG_NVS_ENCRYPTION
            ESP_LOGW("KA", "Encryption is disabled!");
#endif
            _gate_ns->set_u32("id", std::uint32_t(_id));
            _gate_ns->set_blob("keymaker-pubkey", mlab::bin_data::chain(_km_pk.raw_pk()));
            _gate_ns->set_blob("base-key", mlab::bin_data::chain(_base_key));
            _gate_ns->commit();
        } else {
            ESP_LOGE("KA", "Unable to save secret key! This makes all encrypted data ephemeral!");
        }

        return _base_key;
    }


}// namespace ka