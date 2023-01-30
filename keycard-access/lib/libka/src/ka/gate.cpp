//
// Created by spak on 10/1/22.
//

#include <desfire/esp32/utils.hpp>
#include <ka/desfire_fs.hpp>
#include <ka/gate.hpp>
#include <ka/member_token.hpp>
#include <ka/nvs.hpp>
#include <pn532/controller.hpp>
#include <sodium/crypto_kdf_blake2b.h>
#include <sodium/randombytes.h>
#include <sdkconfig.h>


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
        std::array<std::uint8_t, key_type::size> derived_key_data{};
        if (0 != crypto_kdf_blake2b_derive_from_key(
                         derived_key_data.data(), derived_key_data.size(),
                         util::pack_token_id(token_id),
                         app_master_key_context.data(),
                         data())) {
            ESP_LOGE("KA", "Unable to derive root key.");
        }
        return gate_token_key{key_no, derived_key_data};
    }

    void gate::configure(gate_id id, std::string desc, pub_key prog_pub_key) {
        if (app_base_key() == gate_base_key{} or keys().raw_pk() == raw_pub_key{}) {
            ESP_LOGE("KA", "Keys have not been generated for this gate! You must re-query the public key.");
            regenerate_keys();
        }
        ESP_LOGI("KA", "Configuring gate.");
        _id = id;
        _desc = std::move(desc);
        _prog_pk = prog_pub_key;
        ESP_LOGI("KA", "Configured as gate %d: %s", std::uint32_t(this->id()), description().c_str());
        ESP_LOGI("KA", "Gate public key:");
        ESP_LOG_BUFFER_HEX_LEVEL("KA", keys().raw_pk().data(), keys().raw_pk().size(), ESP_LOG_INFO);
        ESP_LOGI("KA", "Programmer public key:");
        ESP_LOG_BUFFER_HEX_LEVEL("KA", programmer_pub_key().raw_pk().data(), programmer_pub_key().raw_pk().size(), ESP_LOG_INFO);
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
        const auto s_id = util::hex_string(id.id);
        ESP_LOGI("GATE", "Authenticated as %s via %s.", id.holder.c_str(), s_id.c_str());
    }
    void gate_responder::on_authentication_fail(desfire::error auth_error, bool might_be_tampering) {
        ESP_LOGE("GATE", "Authentication failed: %s%s.",
                 member_token::describe(auth_error), (might_be_tampering ? " (might be tampering)." : "."));
    }
    void gate_responder::on_activation(pn532::scanner &, pn532::scanned_target const &target) {
        const auto s_id = util::hex_string(target.nfcid);
        ESP_LOGI("GATE", "Activated NFC target %s", s_id.c_str());
    }
    void gate_responder::on_release(pn532::scanner &, pn532::scanned_target const &target) {
        const auto s_id = util::hex_string(target.nfcid);
        ESP_LOGI("GATE", "Released NFC target %s", s_id.c_str());
    }
    void gate_responder::on_leaving_rf(pn532::scanner &, pn532::scanned_target const &target) {
        const auto s_id = util::hex_string(target.nfcid);
        ESP_LOGI("GATE", "NFC target %s has left the RF field.", s_id.c_str());
    }
    void gate_responder::on_failed_scan(pn532::scanner &, pn532::channel::error err) {
        ESP_LOGV("GATE", "Scan failed with error: %s", pn532::to_string(err));
    }

    void gate::config_store(nvs::partition &partition) const {
        ESP_LOGW("KA", "Saving gate configuration.");
        auto ns = partition.open_namespc(ka_namespc);
        if (ns == nullptr) {
            ESP_LOGE("KA", "Unable to create or access NVS namespace.");
            return;
        }
        const auto r_id = ns->set<std::uint32_t>(ka_gid, id());
        const auto r_desc = ns->set<std::string>(ka_desc, description());
        const auto r_prog_pk = ns->set<mlab::bin_data>(ka_prog_pk, mlab::bin_data::chain(programmer_pub_key().raw_pk()));
        const auto r_sk = ns->set<mlab::bin_data>(ka_sk, mlab::bin_data::chain(keys().raw_sk()));
        const auto r_base_key = ns->set<mlab::bin_data>(ka_base_key, mlab::bin_data::chain(app_base_key()));
        const auto r_commit = ns->commit();
        if (not (r_id and r_desc and r_prog_pk and r_sk and r_base_key and r_commit)) {
            ESP_LOGE("KA", "Unable to save gate configuration.");
        }
    }

    void gate::config_store() const {
#ifndef CONFIG_NVS_ENCRYPTION
        ESP_LOGW("KA", "Encryption is disabled!");
#endif
        nvs::nvs nvs{};
        if (auto partition = nvs.open_partition(NVS_DEFAULT_PART_NAME, nvs_encrypted); partition == nullptr) {
            ESP_LOGE("KA", "NVS partition is not available.");
        } else {
            config_store(*partition);
        }
    }
    bool gate::config_load() {
#ifndef CONFIG_NVS_ENCRYPTION
        ESP_LOGW("KA", "Encryption is disabled!");
#endif
        nvs::nvs nvs{};
        if (auto partition = nvs.open_partition(NVS_DEFAULT_PART_NAME, nvs_encrypted); partition == nullptr) {
            ESP_LOGE("KA", "NVS partition is not available.");
            return false;
        } else {
            return config_load(*partition);
        }
    }
    void gate::config_clear() {
#ifndef CONFIG_NVS_ENCRYPTION
        ESP_LOGW("KA", "Encryption is disabled!");
#endif
        nvs::nvs nvs{};
        if (auto partition = nvs.open_partition(NVS_DEFAULT_PART_NAME, nvs_encrypted); partition == nullptr) {
            ESP_LOGE("KA", "NVS partition is not available.");
        } else {
            config_clear(*partition);
        }
    }

    gate gate::load_from_config() {
#ifndef CONFIG_NVS_ENCRYPTION
        ESP_LOGW("KA", "Encryption is disabled!");
#endif
        nvs::nvs nvs{};
        if (auto partition = nvs.open_partition(NVS_DEFAULT_PART_NAME, nvs_encrypted); partition == nullptr) {
            ESP_LOGE("KA", "NVS partition is not available.");
            return gate{};
        } else {
            return load_from_config(*partition);
        }
    }

    gate gate::load_from_config(nvs::partition &partition) {
        gate g{};
        void(g.config_load(partition));
        return g;
    }

    void gate::regenerate_keys() {
        ESP_LOGW("KA", "Generating new gate configuration.");
        *this = gate{};
        _kp.generate_random();
        randombytes_buf(_base_key.data(), _base_key.size());
    }


    namespace {
        [[nodiscard]] nvs::r<mlab::bin_data> assert_size(nvs::r<mlab::bin_data> r_data, std::size_t size, const char *item) {
            if (r_data and r_data->size() != size) {
                ESP_LOGE("KA", "Invalid %s size %d, should be %d.", item, r_data->size(), size);
                // Reject the result
                r_data = nvs::error::invalid_length;
            }
            return r_data;
        }
    }

    bool gate::config_load(nvs::partition &partition) {
        auto ns = partition.open_namespc(ka_namespc);
        if (ns == nullptr) {
            return false;
        }
        ESP_LOGW("KA", "Loading gate configuration.");
        const auto r_id = ns->get<std::uint32_t>(ka_gid);
        const auto r_desc = ns->get<std::string>(ka_desc);
        const auto r_prog_pk = assert_size(ns->get<mlab::bin_data>(ka_prog_pk), raw_pub_key::array_size, "programmer key");
        const auto r_sk = assert_size(ns->get<mlab::bin_data>(ka_sk), raw_sec_key::array_size, "secret key");
        const auto r_base_key = assert_size(ns->get<mlab::bin_data>(ka_base_key), gate_base_key::array_size, "gate app base key");
        if (r_id and r_desc and r_prog_pk and r_sk and r_base_key) {
            _id = gate_id{*r_id};
            _desc = *r_desc;
            // Trim the nul ending character
            _desc.erase(std::find(std::begin(_desc), std::end(_desc), '\0'), std::end(_desc));
            _kp = key_pair{r_sk->data_view()};
            _prog_pk = pub_key{r_prog_pk->data_view()};
            std::copy(std::begin(*r_base_key), std::end(*r_base_key), std::begin(_base_key));
            if (not _kp.is_valid()) {
                ESP_LOGE("KA", "Invalid secret key, rejecting stored configuration.");
            } else {
                return true;
            }
        } else if (r_id or r_desc or r_prog_pk or r_sk or r_base_key) {
            ESP_LOGE("KA", "Incomplete stored configuration, rejecting.");
        }
        return false;
    }

    void gate::config_clear(nvs::partition &partition) {
        auto ns = partition.open_namespc(ka_namespc);
        if (ns == nullptr) {
            ESP_LOGE("KA", "Unable to create or access NVS namespace.");
            return;
        }
        if (not ns->clear() or not ns->commit()) {
            ESP_LOGE("KA", "Unable to config_clear configuration.");
        } else {
            ESP_LOGW("KA", "Cleared configuration.");
        }
    }

}// namespace ka