//
// Created by spak on 10/1/22.
//

#include <desfire/esp32/utils.hpp>
#include <ka/gate.hpp>
#include <ka/member_token.hpp>
#include <ka/nvs.hpp>
#include <ka/p2p_ops.hpp>
#include <ka/secure_p2p.hpp>
#include <mlab/result_macro.hpp>
#include <mlab/strutils.hpp>
#include <pn532/controller.hpp>
#include <sdkconfig.h>
#include <sodium/crypto_kdf_blake2b.h>
#include <sodium/randombytes.h>

#define TAG "GATE"
#undef MLAB_RESULT_LOG_PREFIX
#define MLAB_RESULT_LOG_PREFIX TAG

using namespace std::chrono_literals;

namespace ka {
    namespace {
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
            ESP_LOGE(TAG, "Unable to derive root key.");
        }
        return gate_token_key{key_no, derived_key_data};
    }

    gate_pub_info gate::public_info() const {
        return gate_pub_info{id(), keys().drop_secret_key()};
    }

    r<identity> gate::read_encrypted_gate_file(member_token &token, bool check_app, bool check_file) const {
        return token.read_encrypted_gate_file(id(), keys(), _base_key, keymaker_pk(), check_app, check_file);
    }

    void gate::try_authenticate(member_token &token, gate_auth_responder &responder) const {
        if (const auto r = read_encrypted_gate_file(token, true, true); r) {
            ESP_LOGI(TAG, "Authenticated as %s.", r->holder.c_str());
            responder.on_authentication_success(*r);
        } else {
            switch (r.error()) {
                case desfire::error::app_not_found:
                    [[fallthrough]];
                case desfire::error::file_not_found:
                    ESP_LOGI(TAG, "Not enrolled.");
                    break;
                case desfire::error::app_integrity_error:
                    [[fallthrough]];
                case desfire::error::crypto_error:
                    [[fallthrough]];
                case desfire::error::malformed:
                    [[fallthrough]];
                case desfire::error::file_integrity_error:
                    ESP_LOGW(TAG, "Unable to authenticate, %s", member_token::describe(r.error()));
                    responder.on_authentication_fail(r.error(), true);
                    break;
                default:
                    ESP_LOGW(TAG, "Unable to authenticate, %s", member_token::describe(r.error()));
                    responder.on_authentication_fail(r.error(), false);
                    break;
            }
        }
    }

    std::vector<pn532::target_type> gate_responder::get_scan_target_types(pn532::scanner &) const {
        // Allow both DEP targets (gates to be configured) and Mifare targets
        return {pn532::target_type::dep_passive_424kbps, pn532::target_type::dep_passive_212kbps, pn532::target_type::dep_passive_106kbps,
                pn532::target_type::dep_active_424kbps, pn532::target_type::dep_active_212kbps, pn532::target_type::dep_active_106kbps,
                pn532::target_type::passive_106kbps_iso_iec_14443_4_typea};
    }


    pn532::post_interaction gate_responder::interact(pn532::scanner &scanner, pn532::scanned_target const &target) {
        const auto s_nfcid = mlab::data_to_hex_string(target.nfcid);
        ESP_LOGI(TAG, "Found %s target with NFC ID %s.", pn532::to_string(target.type), s_nfcid.c_str());
        if (target.type == pn532::target_type::passive_106kbps_iso_iec_14443_4_typea) {
            return member_token_responder::interact(scanner, target);
        } else {
            // Enter a gate configuration loop
            _g.serve_remote_gate(scanner.ctrl(), target.index);
        }
        return pn532::post_interaction::reject;
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
        ESP_LOGV("GATE", "Scan failed  with error: %s", pn532::to_string(err));
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

    gate::gate(std::shared_ptr<nvs::partition> const &partition) : device{partition} {
        if (partition) {
            _gate_ns = partition->open_namespc("ka-gate");
        }
        if (_gate_ns) {
            auto load_from_nvs = [&]() -> bool {
                if (const auto r = _gate_ns->get_u32("id"); r) {
                    _id = gate_id{*r};
                } else if (r.error() == nvs::error::not_found) {
                    return false;// Set up as new gate
                } else {
                    ESP_LOGE(TAG, "Unable to retrieve %s, %s error", "gate id", to_string(r.error()));
                }
                if (const auto r = _gate_ns->get_parse_blob<pub_key>("keymaker-pubkey"); r) {
                    _km_pk = *r;
                } else if (r.error() == nvs::error::not_found) {
                    return false;// Set up as new gate
                } else {
                    ESP_LOGE(TAG, "Unable to retrieve %s, %s error", "public key", to_string(r.error()));
                }
                if (const auto r = _gate_ns->get_parse_blob<gate_base_key>("base-key"); r) {
                    _base_key = *r;
                } else if (r.error() == nvs::error::not_found) {
                    return false;// Set up as new gate
                } else {
                    ESP_LOGE(TAG, "Unable to retrieve %s, %s error", "app base key", to_string(r.error()));
                }
                return true;
            };

            if (not load_from_nvs()) {
                // Reset
                _id = std::numeric_limits<gate_id>::max();
                _km_pk = {};
                _base_key = {};
            }
        }
    }

    gate::gate(key_pair kp) : device{kp} {}

    gate::gate(key_pair kp, gate_id gid, pub_key keymaker_pubkey, gate_base_key base_key)
        : device{kp},
          _id{gid},
          _km_pk{keymaker_pubkey},
          _base_key{base_key} {}

    void gate::reset() {
        ESP_LOGW(TAG, "Gate is being reset.");
        _id = std::numeric_limits<gate_id>::max();
        _km_pk = {};
        _base_key = {};
        if (_gate_ns) {
            void([&]() -> nvs::r<> {
                TRY(_gate_ns->erase("id"));
                TRY(_gate_ns->erase("keymaker-pubkey"));
                TRY(_gate_ns->erase("base-key"));
                TRY(_gate_ns->commit());
                return mlab::result_success;
            }());
        }
        device::generate_keys();
    }

    gate_token_key gate::derive_token_key(const ka::token_id &token_id, std::uint8_t key_no) const {
        return _base_key.derive_token_key(token_id, key_no);
    }

    std::optional<gate_base_key> gate::configure(gate_id gid, pub_key keymaker_pubkey) {
        if (is_configured()) {
            ESP_LOGE(TAG, "Attempt to reconfigure gate %lu as gate %lu with the following public key:",
                     std::uint32_t(id()), std::uint32_t(gid));
            ESP_LOG_BUFFER_HEX_LEVEL(TAG, keymaker_pubkey.raw_pk().data(), keymaker_pubkey.raw_pk().size(), ESP_LOG_ERROR);
            return std::nullopt;
        }
        ESP_LOGI(TAG, "Configuring as gate %lu, with the following keymaker pubkey:", std::uint32_t(gid));
        ESP_LOG_BUFFER_HEX_LEVEL(TAG, keymaker_pubkey.raw_pk().data(), keymaker_pubkey.raw_pk().size(), ESP_LOG_INFO);
        _id = gid;
        _km_pk = keymaker_pubkey;
        // Generate a new app base key
        randombytes_buf(_base_key.data(), _base_key.size());

        if (_gate_ns) {
#ifndef CONFIG_NVS_ENCRYPTION
            ESP_LOGW(TAG, "Encryption is disabled!");
#endif
            auto update_nvs = [&]() -> nvs::r<> {
                TRY(_gate_ns->set_u32("id", std::uint32_t(_id)));
                TRY(_gate_ns->set_encode_blob("keymaker-pubkey", _km_pk));
                TRY(_gate_ns->set_encode_blob("base-key", _base_key));
                TRY(_gate_ns->commit());
                return mlab::result_success;
            };

            if (not update_nvs()) {
                ESP_LOGE(TAG, "Unable to save secret key! This makes all encrypted data ephemeral!");
            }
        }

        return _base_key;
    }

    void gate::serve_remote_gate(pn532::controller &ctrl, std::uint8_t logical_idx) {
        auto raw_initiator = std::make_shared<pn532::p2p::pn532_initiator>(ctrl, logical_idx);
        auto sec_initiator = std::make_shared<p2p::secure_initiator>(raw_initiator, keys());
        p2p::local_gate lg{*this, sec_initiator};
        lg.serve_loop();
    }


}// namespace ka