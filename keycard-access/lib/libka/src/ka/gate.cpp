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
        constexpr auto ka_base_key = "gate-base-key";
    }// namespace

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

    r<identity> gate::try_authenticate(member_token &token) const {
        r<token_id> r_id = token.get_id();
        if (not r_id) {
            ESP_LOGE("KA", "Unable to obtain token id, %s", desfire::to_string(r_id.error()));
            return desfire::error::authentication_error;
        }
        ESP_LOGI("KA", "Tag declares token id:");
        ESP_LOG_BUFFER_HEX_LEVEL("KA", r_id->data(), r_id->size(), ESP_LOG_INFO);
        // Attempt first to authenticate the identity, and, at least, this id
        const ticket auth_ticket{keys().derive_auth_ticket(*r_id, context_data())};
        auto r_identity = token.authenticate(id(), auth_ticket);
        if (r_identity) {
            ESP_LOGI("KA", "Authenticated as %s.", r_identity->holder.c_str());
        }
        return r_identity;
    }

    r<identity> gate::try_complete_enrollment(member_token &token) const {
        ESP_LOGW("KA", "Not implemented yet");
        return desfire::error::command_aborted;
    }

    bool gate::try_process_service_messages(member_token &token) {
        ESP_LOGW("KA", "Not implemented yet");
        return true;
    }

    void gate::interact_with_token(member_token &token) {
        auto r_identity = try_authenticate(token);
        auto r_status = token.get_gate_status(id());
        if (not r_status) {
            ESP_LOGE("KA", "Unable to get gate status, %s", desfire::to_string(r_status.error()));
            return;
        }
        // Do not accept anything from auth ready tags which do not pass authentication or are broken
        if (*r_status == gate_status::auth_ready and not r_identity) {
            ESP_LOGE("KA", "Incorrect claimed identity.");
            return;
        } else if (*r_status == gate_status::broken) {
            ESP_LOGE("KA", "Broken gate status.");
            return;
        }
        // Import service messages if there are any
        if (not try_process_service_messages(token)) {
            return;
        }
        // Check if the gate has to be enrolled, and we can
        if (*r_status == gate_status::enrolled) {
            r_identity = try_complete_enrollment(token);
        }
        if (r_identity) {
            ESP_LOGI("KA", "Authenticated as %s (%s)", r_identity->holder.c_str(), r_identity->publisher.c_str());
            // TODO Callback.
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
        _base_key = gate_app_base_key{0, desfire::random_oracle{randombytes_buf}};
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
        auto try_load_base_key = [&](const mlab::bin_data &data) -> bool {
            if (data.size() == gate_app_base_key::size) {
                key_type::key_data kd{};
                std::copy(std::begin(data), std::end(data), std::begin(kd));
                _base_key = gate_app_base_key{0, kd};
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