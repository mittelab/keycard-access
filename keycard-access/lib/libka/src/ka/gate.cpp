//
// Created by spak on 10/1/22.
//

#include <ka/member_token.hpp>
#include <desfire/esp32/cipher_provider.hpp>
#include <ka/gate.hpp>
#include <ka/nvs.hpp>
#include <pn532/controller.hpp>
#include <pn532/desfire_pcd.hpp>

using namespace std::chrono_literals;

namespace ka {

    namespace {
        constexpr auto ka_namespc = "keycard-access";
        constexpr auto ka_sk = "secret-key";
        constexpr auto ka_desc = "description";
        constexpr auto ka_gid = "gate-id";
        constexpr auto ka_prog_pk = "programmer-key";
    }

    void gate::configure(gate_id id, std::string desc, pub_key prog_pub_key) {
        _id = id;
        _desc = std::move(desc);
        _prog_pk = prog_pub_key;
    }

    void gate::interact_with_token(member_token &token) {

    }

    void gate::loop(pn532::controller &controller) {
        using cipher_provider = desfire::esp32::default_cipher_provider;
        while (true) {
            const auto r = controller.initiator_list_passive_kbps106_typea(1, 10s);
            if (not r or r->empty()) {
                continue;
            }
            // A card was scanned!
            ESP_LOGI("KA", "Found passive target with NFC ID:");
            ESP_LOG_BUFFER_HEX_LEVEL("KA", r->front().info.nfcid.data(), r->front().info.nfcid.size(), ESP_LOG_INFO);
            auto tag = desfire::tag::make<cipher_provider>(pn532::desfire_pcd{controller, r->front().logical_index});
            member_token token{tag};
            interact_with_token(token);
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
        const auto r_prog_pk =ns->set<mlab::bin_data>(ka_prog_pk, mlab::bin_data::chain(programmer_pub_key().raw_pk()));
        const auto r_sk =ns->set<mlab::bin_data>(ka_sk, mlab::bin_data::chain(key_pair().raw_sk()));
        if (not (r_id and r_desc and r_prog_pk and r_sk)) {
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
    }

    bool gate::load(nvs::partition &partition) {
        auto try_load_key_pair = [&](mlab::bin_data const &data) -> bool {
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
        };
        auto try_load_programmer_key = [&](const mlab::bin_data &data) -> bool{
            if (data.size() == raw_pub_key::key_size) {
                _prog_pk = pub_key{data.data_view()};
                return true;
            } else {
                ESP_LOGE("KA", "Invalid programmer key size.");
            }
            return false;
        };
        auto ns = partition.open_namespc(ka_namespc);
        if (ns == nullptr) {
            return false;
        }
        ESP_LOGW("KA", "Loading gate configuration.");
        const auto r_id = ns->get<gate_id>(ka_gid);
        const auto r_desc = ns->get<std::string>(ka_desc);
        const auto r_prog_pk =ns->get<mlab::bin_data>(ka_prog_pk);
        const auto r_sk =ns->get<mlab::bin_data>(ka_sk);
        if (r_id and r_desc and r_prog_pk and r_sk) {
            if (try_load_key_pair(*r_sk) and try_load_programmer_key(*r_prog_pk)) {
                // Load also all the rest
                _id = *r_id;
                _desc = *r_desc;
                return true;
            } else {
                ESP_LOGE("KA", "Invalid secret key or programmer key, rejecting stored configuration.");
            }
        } else if (r_id or r_desc or r_prog_pk or r_sk) {
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

}