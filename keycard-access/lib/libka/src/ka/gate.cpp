//
// Created by spak on 10/1/22.
//

#include <desfire/esp32/cipher_provider.hpp>
#include <desfire/esp32/utils.hpp>
#include <ka/desfire_fs.hpp>
#include <ka/gate.hpp>
#include <ka/member_token.hpp>
#include <ka/nvs.hpp>
#include <pn532/controller.hpp>
#include <pn532/desfire_pcd.hpp>
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

    gate_config gate::configure(gate_id id, std::string desc, pub_key prog_pub_key) {
        ESP_LOGI("KA", "Configuring gate.");
        generate();
        _id = id;
        _desc = std::move(desc);
        _prog_pk = prog_pub_key;
        ESP_LOGI("KA", "Configured as gate %d: %s", this->id(), description().c_str());
        ESP_LOGI("KA", "Gate public key:");
        ESP_LOG_BUFFER_HEX_LEVEL("KA", keys().raw_pk().data(), keys().raw_pk().size(), ESP_LOG_INFO);
        ESP_LOGI("KA", "Programmer public key:");
        ESP_LOG_BUFFER_HEX_LEVEL("KA", programmer_pub_key().raw_pk().data(), programmer_pub_key().raw_pk().size(), ESP_LOG_INFO);
        return {this->id(), pub_key{keys().raw_pk()}, app_base_key()};
    }


    void gate::try_authenticate(member_token &token, gate_responder &responder) const {
        if (const auto r = token.is_gate_enrolled(id()); r and *r) {
            // We should be able to get the id
            if (const auto r_id = token.get_id(); r_id) {
                responder.on_authentication_begin(*r_id);
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

    void gate::loop(pn532::controller &controller, gate_responder &responder) const {
        using cipher_provider = desfire::esp32::default_cipher_provider;
        bool wait_for_removal = false;
        token_id last_target{};
        while (true) {
            // If we are waiting for removal, be fast.
            auto suppress = desfire::esp32::suppress_log{ESP_LOG_ERROR, {PN532_TAG}};
            const auto r = controller.initiator_list_passive_kbps106_typea(1, wait_for_removal ? 500ms : 10s);
            suppress.restore();
            if (not r or r->empty()) {
                if (wait_for_removal) {
                    // Card was removed
                    wait_for_removal = false;
                    responder.on_removal(last_target);
                    last_target = {};
                }
                continue;
            }
            const token_id current_target = id_from_nfc_id(r->front().info.nfcid);
            if (not wait_for_removal or last_target != current_target) {
                ESP_LOGI("KA", "Found passive target with NFC ID:");
                ESP_LOG_BUFFER_HEX_LEVEL("KA", current_target.data(), current_target.size(), ESP_LOG_INFO);
                responder.on_approach(current_target);
                auto tag = desfire::tag::make<cipher_provider>(pn532::desfire_pcd{controller, r->front().logical_index});
                member_token token{tag};
                try_authenticate(token, responder);
                responder.on_interaction_complete(current_target);
            }
            // Now we will poll every 500ms to see when the release this card
            wait_for_removal = true;
            last_target = current_target;
            controller.initiator_release(r->front().logical_index);
        }
    }

    void gate::store(nvs::partition &partition) const {
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
        if (not(r_id and r_desc and r_prog_pk and r_sk and r_base_key)) {
            ESP_LOGE("KA", "Unable to save gate configuration.");
        }
    }

    gate gate::load_or_generate(nvs::partition &partition) {
        gate g{};
        if (not g.load(partition)) {
            g.generate();
            g.store(partition);
        }
        return g;
    }

    gate gate::load_or_generate() {
        nvs::nvs nvs{};
        auto partition = nvs.open_partition(NVS_DEFAULT_PART_NAME, false);
        if (partition == nullptr) {
            ESP_LOGE("KA", "NVS partition is not available.");
            gate g{};
            g.generate();
            return g;
        }
        return load_or_generate(*partition);
    }

    void gate::generate() {
        ESP_LOGW("KA", "Generating new gate configuration.");
        *this = gate{};
        _kp.generate_random();
        randombytes_buf(_base_key.data(), _base_key.size());
    }

    bool gate::load(nvs::partition &partition) {
        auto try_load_key_pair = [&](mlab::bin_data const &data) -> bool {
            if (data.size() == raw_sec_key::array_size) {
                // Attempt at reading
                ka::key_pair kp{data.data_view()};
                if (kp.is_valid()) {
                    _kp = kp;
                    return true;
                }
                ESP_LOGE("KA", "Invalid secret key.");
            } else {
                ESP_LOGE("KA", "Invalid secret key size.");
            }
            return false;
        };
        auto try_load_programmer_key = [&](const mlab::bin_data &data) -> bool {
            if (data.size() == raw_pub_key::array_size) {
                _prog_pk = pub_key{data.data_view()};
                return true;
            }
            ESP_LOGE("KA", "Invalid programmer key size.");
            return false;
        };
        auto try_load_base_key = [&](const mlab::bin_data &data) -> bool {
            if (data.size() == gate_app_base_key::array_size) {
                std::copy(std::begin(data), std::end(data), std::begin(_base_key));
                return true;
            }
            ESP_LOGE("KA", "Invalid gate app base key size.");
            return false;
        };
        auto ns = partition.open_namespc(ka_namespc);
        if (ns == nullptr) {
            return false;
        }
        ESP_LOGW("KA", "Loading gate configuration.");
        const auto r_id = ns->get<gate_id>(ka_gid);
        const auto r_desc = ns->get<std::string>(ka_desc);
        const auto r_prog_pk = ns->get<mlab::bin_data>(ka_prog_pk);
        const auto r_sk = ns->get<mlab::bin_data>(ka_sk);
        const auto r_base_key = ns->get<mlab::bin_data>(ka_base_key);
        if (r_id and r_desc and r_prog_pk and r_sk and r_base_key) {
            if (
                    try_load_key_pair(*r_sk) and
                    try_load_programmer_key(*r_prog_pk) and
                    try_load_base_key(*r_base_key)) {
                // Load also all the rest
                _id = *r_id;
                _desc = *r_desc;
                return true;
            } else {
                ESP_LOGE("KA", "Invalid secret key or programmer key, rejecting stored configuration.");
            }
        } else if (r_id or r_desc or r_prog_pk or r_sk or r_base_key) {
            ESP_LOGE("KA", "Incomplete stored configuration, rejecting.");
        }
        return false;
    }

    void gate::clear(nvs::partition &partition) {
        auto ns = partition.open_namespc(ka_namespc);
        if (ns == nullptr) {
            ESP_LOGE("KA", "Unable to create or access NVS namespace.");
            return;
        }
        if (not ns->clear()) {
            ESP_LOGE("KA", "Unable to clear configuration.");
        } else {
            ESP_LOGW("KA", "Cleared configuration.");
        }
    }

}// namespace ka