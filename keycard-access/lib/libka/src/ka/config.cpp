//
// Created by spak on 10/2/22.
//

#include <ka/config.hpp>
#include <ka/nvs.hpp>

namespace ka {
    namespace {
        constexpr auto ka_namespc = "keycard-access";
        constexpr auto ka_sk = "secret-key";
        constexpr auto ka_desc = "description";
        constexpr auto ka_gid = "gate-id";
        constexpr auto ka_prog_pk = "programmer-key";
    }

    bool gate_config::try_load_key_pair(mlab::bin_data const &data) {
        if (data.size() == raw_sec_key::key_size) {
            // Attempt at reading
            ka::key_pair kp{data.data_view()};
            if (kp.is_valid()) {
                _kp = kp;
                return true;
            } else {
                ESP_LOGE("KA", "Invalid secret key.");
            }
        } else {
            ESP_LOGE("KA", "Invalid secret key size.");
        }
        return false;
    }

    bool gate_config::try_load_programmer_key(const mlab::bin_data &data) {
        if (data.size() == raw_pub_key::key_size) {
            _prog_pk = pub_key{data.data_view()};
            return true;
        } else {
            ESP_LOGE("KA", "Invalid programmer key size.");
        }
        return false;
    }

    void gate_config::save_to_nvs(nvs::partition &partition, gate_config const &cfg) {
        ESP_LOGW("KA", "Saving configuration.");
        auto ns = partition.open_namespc(ka_namespc);
        if (ns == nullptr) {
            ESP_LOGE("KA", "Unable to create or access NVS namespace.");
            return;
        }
        const auto r_id = ns->set<gate_id>(ka_gid, cfg.id());
        const auto r_desc = ns->set<std::string>(ka_desc, cfg.description());
        const auto r_prog_pk =ns->set<mlab::bin_data>(ka_prog_pk, mlab::bin_data::chain(cfg.programmer_pub_key().raw_pk()));
        const auto r_sk =ns->set<mlab::bin_data>(ka_sk, mlab::bin_data::chain(key_pair().raw_sk()));
        if (not (r_id and r_desc and r_prog_pk and r_sk)) {
            ESP_LOGE("KA", "Unable to save configuration.");
        }
    }

    gate_config gate_config::generate() {
        ESP_LOGW("KA", "Generating new configuration.");
        gate_config cfg{};
        cfg._kp.generate_random();
        return cfg;
    }

    void gate_config::clear_nvs(nvs::partition &partition) {
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

    gate_config gate_config::load_from_nvs(nvs::partition &partition) {
        gate_config cfg{};
        if (auto ns = partition.open_const_namespc(ka_namespc); ns != nullptr) {
            const auto r_id = ns->get<gate_id>(ka_gid);
            const auto r_desc = ns->get<std::string>(ka_desc);
            const auto r_prog_pk =ns->get<mlab::bin_data>(ka_prog_pk);
            const auto r_sk =ns->get<mlab::bin_data>(ka_sk);
            if (r_id and r_desc and r_prog_pk and r_sk) {
                if (cfg.try_load_key_pair(*r_sk) and cfg.try_load_programmer_key(*r_prog_pk)) {
                    // Load also all the rest
                    cfg._id = *r_id;
                    cfg._desc = *r_desc;
                    return cfg;
                } else {
                    ESP_LOGE("KA", "Invalid secret key or programmer key, rejecting stored configuration.");
                }
            } else if (r_id or r_desc or r_prog_pk or r_sk) {
                ESP_LOGE("KA", "Incomplete stored configuration, rejecting.");
            }
        }
        cfg = gate_config::generate();
        gate_config::save_to_nvs(partition, cfg);
        return cfg;
    }

}// namespace ka