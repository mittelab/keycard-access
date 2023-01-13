//
// Created by spak on 10/1/22.
//

#include <ka/desfire_fs.hpp>
#include <desfire/esp32/cipher_provider.hpp>
#include <ka/gate.hpp>
#include <ka/member_token.hpp>
#include <ka/nvs.hpp>
#include <ka/ticket.hpp>
#include <pn532/controller.hpp>
#include <pn532/desfire_pcd.hpp>
#include <sodium/crypto_kdf_blake2b.h>
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


    r<> gate::interact_with_token(member_token &token) {
        TRY_RESULT(token.is_gate_enrolled(id())) {
            if (not *r) {
                // Not enrolled, nothing to do.
                ESP_LOGI("KA", "Not enrolled.");
                return mlab::result_success;
            }
        }
        // Should be authenticable
        TRY_RESULT_AS(token.get_id(), r_id) {
            const auto r_auth = token.authenticate(id(), app_base_key().derive_app_master_key(*r_id));
            if (r_auth) {
                ESP_LOGI("KA", "Authenticated as %s.", r_auth->holder.c_str());
                // TODO Callback;
                return mlab::result_success;
            } else if (might_be_tampering(r_auth.error())) {
                ESP_LOGW("KA", "Authentication error might indicate tampering: %s", desfire::to_string(r_auth.error()));
                // TODO Callback;
            }
            return r_auth.error();
        }
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
        const auto r_prog_pk = ns->set<mlab::bin_data>(ka_prog_pk, mlab::bin_data::chain(programmer_pub_key().raw_pk()));
        const auto r_sk = ns->set<mlab::bin_data>(ka_sk, mlab::bin_data::chain(key_pair().raw_sk()));
        const auto r_ctx = ns->set<mlab::bin_data>(ka_ctx, mlab::bin_data::chain(context_data()));
        const auto r_base_key = ns->set<mlab::bin_data>(ka_base_key, mlab::bin_data::chain(app_base_key().data()));
        if (not(r_id and r_desc and r_prog_pk and r_sk and r_ctx and r_base_key)) {
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
        randombytes_buf(_ctx.data(), _ctx.size());
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
        auto try_load_context_data = [&](const mlab::bin_data &data) -> bool {
            if (data.size() == _ctx.size()) {
                std::copy(std::begin(data), std::end(data), std::begin(_ctx));
                return true;
            }
            ESP_LOGE("KA", "Invalid context data size.");
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
        const auto r_ctx = ns->get<mlab::bin_data>(ka_ctx);
        const auto r_base_key = ns->get<mlab::bin_data>(ka_base_key);
        if (r_id and r_desc and r_prog_pk and r_sk and r_ctx and r_base_key) {
            if (
                    try_load_key_pair(*r_sk) and
                    try_load_programmer_key(*r_prog_pk) and
                    try_load_context_data(*r_ctx) and
                    try_load_base_key(*r_base_key)) {
                // Load also all the rest
                _id = *r_id;
                _desc = *r_desc;
                return true;
            } else {
                ESP_LOGE("KA", "Invalid secret key or programmer key, rejecting stored configuration.");
            }
        } else if (r_id or r_desc or r_prog_pk or r_sk or r_ctx or r_base_key) {
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