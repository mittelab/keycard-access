//
// Created by spak on 10/1/22.
//

#include <desfire/esp32/cipher_provider.hpp>
#include <ka/gate.hpp>
#include <ka/member_token.hpp>
#include <ka/nvs.hpp>
#include <ka/ticket.hpp>
#include <pn532/controller.hpp>
#include <pn532/desfire_pcd.hpp>
#include <sodium/randombytes.h>

using namespace std::chrono_literals;

namespace mlab {
    template <std::size_t N>
    bin_data &operator<<(bin_data &bd, std::array<char, N> const &a) {
        const auto view = mlab::range(
                reinterpret_cast<std::uint8_t const *>(a.data()),
                reinterpret_cast<std::uint8_t const *>(a.data() + a.size())
        );
        return bd << view;
    }
}

namespace ka {

    namespace {
        constexpr auto ka_namespc = "keycard-access";
        constexpr auto ka_sk = "secret-key";
        constexpr auto ka_desc = "description";
        constexpr auto ka_gid = "gate-id";
        constexpr auto ka_prog_pk = "programmer-key";
        constexpr auto ka_ctx = "context-data";
    }// namespace

    void gate::configure(gate_id id, std::string desc, pub_key prog_pub_key) {
        _id = id;
        _desc = std::move(desc);
        _prog_pk = prog_pub_key;
    }

    void gate::interact_with_token(member_token &token, token_id const &nfc_id) {
        // Derive an authentication ticket to test
        auto [key, salt] = keys().derive_auth_ticket(nfc_id, context_data());
        if (const auto r_id = token.authenticate(id(), ticket{key, salt}); r_id) {
            ESP_LOGI("KA", "Authenticated as %s.", r_id->holder.c_str());
            return;
        }
        // TODO: assert gate status and check for enrollment
        ESP_LOGW("KA", "Not implemented yet.");
    }

    void gate::loop(pn532::controller &controller) {
        using cipher_provider = desfire::esp32::default_cipher_provider;
        while (true) {
            const auto r = controller.initiator_list_passive_kbps106_typea(1, 10s);
            if (not r or r->empty()) {
                continue;
            }
            // A card was scanned!
            token_id id_from_nfc{};
            if (id_from_nfc.size() != r->front().info.nfcid.size()) {
                ESP_LOGE("KA", "NFC ID should be %d bytes long?!", id_from_nfc.size());
                continue;
            }
            std::copy_n(std::begin(r->front().info.nfcid), id_from_nfc.size(), std::begin(id_from_nfc));
            ESP_LOGI("KA", "Found passive target with NFC ID:");
            ESP_LOG_BUFFER_HEX_LEVEL("KA", id_from_nfc.data(), id_from_nfc.size(), ESP_LOG_INFO);
            auto tag = desfire::tag::make<cipher_provider>(pn532::desfire_pcd{controller, r->front().logical_index});
            member_token token{tag};
            interact_with_token(token, id_from_nfc);
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
        const auto r_ctx = ns->set<mlab::bin_data>(ka_ctx, mlab::bin_data::chain(context_data()));
        if (not(r_id and r_desc and r_prog_pk and r_sk and r_ctx)) {
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
        randombytes_buf(_ctx.data(), _ctx.size());
    }

    bool gate::load(nvs::partition &partition) {
        auto try_load_key_pair = [&](mlab::bin_data const &data) -> bool {
            if (data.size() == raw_sec_key::key_size) {
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
            if (data.size() == raw_pub_key::key_size) {
                _prog_pk = pub_key{data.data_view()};
                return true;
            }
            ESP_LOGE("KA", "Invalid programmer key size.");
            return false;
        };
        auto try_load_context_data = [&](const mlab::bin_data &data) -> bool {
            if (data.size() == _ctx.size()) {
                std::copy(std::begin(data), std::end(data), std::begin(_ctx));
                return true;
            }
            ESP_LOGE("KA", "Invalid context data size.");
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
        const auto r_ctx = ns->get<mlab::bin_data>(ka_ctx);
        if (r_id and r_desc and r_prog_pk and r_sk and r_ctx) {
            if (try_load_key_pair(*r_sk) and try_load_programmer_key(*r_prog_pk) and try_load_context_data(*r_ctx)) {
                // Load also all the rest
                _id = *r_id;
                _desc = *r_desc;
                return true;
            } else {
                ESP_LOGE("KA", "Invalid secret key or programmer key, rejecting stored configuration.");
            }
        } else if (r_id or r_desc or r_prog_pk or r_sk or r_ctx) {
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