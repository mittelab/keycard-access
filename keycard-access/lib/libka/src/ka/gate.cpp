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

        [[nodiscard]] bool might_be_tampering(desfire::error e) {
            switch (e) {
                case desfire::error::authentication_error:
                    [[fallthrough]];
                case desfire::error::file_integrity_error:
                    // Wrong hash
                    [[fallthrough]];
                case desfire::error::length_error:
                    // Wrong hash length
                    [[fallthrough]];
                case desfire::error::permission_denied:
                    return true;
                default:
                    return false;
            }
        }

        [[nodiscard]] token_id id_from_nfc_id(std::vector<std::uint8_t> const &d) {
            if (d.size() != token_id::array_size) {
                ESP_LOGE("KA", "NFC ID should be %d bytes long, not %d.", token_id::array_size, d.size());
            }
            token_id id{};
            std::copy_n(std::begin(d), std::min(token_id::array_size, d.size()), std::begin(id));
            return id;
        }
    }// namespace

    static_assert(gate_app_base_key::array_size == crypto_kdf_blake2b_KEYBYTES);

    gate_app_master_key gate_app_base_key::derive_app_master_key(const token_id &token_id) const {
        std::array<std::uint8_t, key_type::size> derived_key_data{};
        if (0 != crypto_kdf_blake2b_derive_from_key(
                         derived_key_data.data(), derived_key_data.size(),
                         pack_token_id(token_id),
                         app_master_key_context.data(),
                         data())) {
            ESP_LOGE("KA", "Unable to derive root key.");
        }
        return gate_app_master_key{0, derived_key_data};
    }

    void gate::configure(gate_id id, std::string desc, pub_key prog_pub_key) {
        if (app_base_key() == gate_app_base_key{} or keys().raw_pk() == raw_pub_key{}) {
            ESP_LOGE("KA", "Keys have not been generated for this gate! You must re-query the public key.");
            regenerate_keys();
        }
        ESP_LOGI("KA", "Configuring gate.");
        _id = id;
        _desc = std::move(desc);
        _prog_pk = prog_pub_key;
        ESP_LOGI("KA", "Configured as gate %d: %s", this->id(), description().c_str());
        ESP_LOGI("KA", "Gate public key:");
        ESP_LOG_BUFFER_HEX_LEVEL("KA", keys().raw_pk().data(), keys().raw_pk().size(), ESP_LOG_INFO);
        ESP_LOGI("KA", "Programmer public key:");
        ESP_LOG_BUFFER_HEX_LEVEL("KA", programmer_pub_key().raw_pk().data(), programmer_pub_key().raw_pk().size(), ESP_LOG_INFO);
    }


    void gate::try_authenticate(member_token &token, gate_auth_responder &responder) const {
        if (const auto r = token.is_gate_enrolled(id()); r and *r) {
            // We should be able to get the id
            if (const auto r_id = token.get_id(); r_id) {
                if (const auto r_auth = token.authenticate(id(), app_base_key().derive_app_master_key(*r_id)); r_auth) {
                    ESP_LOGI("KA", "Authenticated as %s.", r_auth->holder.c_str());
                    responder.on_authentication_success(*r_auth);
                } else {
                    const bool tampering = might_be_tampering(r_auth.error());
                    if (tampering) {
                        ESP_LOGW("KA", "Authentication error might indicate tampering: %s", desfire::to_string(r_auth.error()));
                    }
                    responder.on_authentication_fail(*r_id, r_auth.error(), token.get_identity(), tampering);
                }
            } else {
                ESP_LOGW("KA", "Enrolled but invalid MAD, error: %s", desfire::to_string(r_id.error()));
            }
        } else if (r and not *r) {
            ESP_LOGI("KA", "Not enrolled.");
        }
    }

    pn532::post_interaction gate_responder::interact_token(member_token &token) {
        if (_g.is_configured()) {
            _g.try_authenticate(token, *this);
        }
        return pn532::post_interaction::reject;
    }

    void gate_responder::on_authentication_success(identity const &id) {
        const auto s_id = util::hex_string(id.id);
        ESP_LOGI("GATE", "Authenticated as %s via %s.", id.holder.c_str(), s_id.c_str());
    }
    void gate_responder::on_authentication_fail(token_id const &id, desfire::error auth_error, r<identity> const &unverified_id, bool might_be_tampering) {
        const auto s_id = util::hex_string(id);
        if (unverified_id) {
            ESP_LOGE("GATE", "Authentication failed (%s): token %s claims to be %s%s.",
                     desfire::to_string(auth_error), s_id.c_str(), unverified_id->holder.c_str(),
                     (might_be_tampering ? " (might be tampering)." : "."));
        } else {
            ESP_LOGE("GATE", "Authentication failed (%s) on token %s%s.",
                     desfire::to_string(auth_error), s_id.c_str(), (might_be_tampering ? " (might be tampering)." : "."));
        }
    }
    void gate_responder::on_activation(pn532::scanner &, pn532::scanned_target const &target) {
        const auto s_id = util::hex_string({target.nfcid.data(), target.nfcid.data() + target.nfcid.size()});
        ESP_LOGI("GATE", "Activated NFC target %s", s_id.c_str());
    }
    void gate_responder::on_release(pn532::scanner &, pn532::scanned_target const &target) {
        const auto s_id = util::hex_string({target.nfcid.data(), target.nfcid.data() + target.nfcid.size()});
        ESP_LOGI("GATE", "Released NFC target %s", s_id.c_str());
    }
    void gate_responder::on_leaving_rf(pn532::scanner &, pn532::scanned_target const &target) {
        const auto s_id = util::hex_string({target.nfcid.data(), target.nfcid.data() + target.nfcid.size()});
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
        const auto r_id = ns->set<gate_id>(ka_gid, id());
        const auto r_desc = ns->set<std::string>(ka_desc, description());
        const auto r_prog_pk = ns->set<mlab::bin_data>(ka_prog_pk, mlab::bin_data::chain(programmer_pub_key().raw_pk()));
        const auto r_sk = ns->set<mlab::bin_data>(ka_sk, mlab::bin_data::chain(key_pair().raw_sk()));
        const auto r_base_key = ns->set<mlab::bin_data>(ka_base_key, mlab::bin_data::chain(app_base_key().data()));
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
        const auto r_id = ns->get<gate_id>(ka_gid);
        const auto r_desc = ns->get<std::string>(ka_desc);
        const auto r_prog_pk = assert_size(ns->get<mlab::bin_data>(ka_prog_pk), raw_pub_key::array_size, "programmer key");
        const auto r_sk = assert_size(ns->get<mlab::bin_data>(ka_sk), raw_sec_key::array_size, "secret key");
        const auto r_base_key = assert_size(ns->get<mlab::bin_data>(ka_base_key), gate_app_base_key::array_size, "gate app base key");
        if (r_id and r_desc and r_prog_pk and r_sk and r_base_key) {
            _id = *r_id;
            _desc = *r_desc;
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