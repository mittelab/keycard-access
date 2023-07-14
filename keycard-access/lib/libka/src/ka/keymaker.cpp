//
// Created by spak on 6/14/23.
//

#include <desfire/esp32/utils.hpp>
#include <esp_log.h>
#include <ka/console.hpp>
#include <ka/keymaker.hpp>
#include <ka/secure_p2p.hpp>
#include <mlab/result_macro.hpp>
#include <mlab/strutils.hpp>

#define TAG "KEYM"

#undef MLAB_RESULT_LOG_PREFIX
#define MLAB_RESULT_LOG_PREFIX TAG

namespace ka {
    namespace p2p {
        template <class T>
        concept remote_gate_protocol = std::is_base_of_v<remote_gate_base, T>;
    }

    using namespace ka::cmd_literals;

    const char *to_string(gate_status gs) {
        switch (gs) {
            case gate_status::initialized:
                return "initialized";
            case gate_status::configured:
                return "configured";
            case gate_status::deleted:
                return "deleted";
            default:
                return "unknown";
        }
    }


    keymaker::keymaker(std::shared_ptr<nvs::partition> const &partition, std::shared_ptr<pn532::controller> ctrl)
        : device{partition},
          _ctrl{std::move(ctrl)} {
        // Turn off the field, we will turn it on on-demand
        if (_ctrl) {
            void([&]() -> pn532::result<> {
                TRY(_ctrl->rf_configuration_field(false, false));
                return mlab::result_success;
            }());
        }
        if (not partition) {
            return;
        }
        if (_gate_ns = partition->open_namespc("ka-gates"); _gate_ns) {
            _gates = keymaker_gate_data::load_from(*_gate_ns);
        }
    }

    keymaker::keymaker(key_pair kp)
        : device{kp} {}

    class keymaker::card_channel {
        std::shared_ptr<pn532::controller> _ctrl = {};
        std::shared_ptr<pn532::desfire_pcd> _pcd = {};
        std::unique_ptr<desfire::tag> _tag = {};
        token_id _tkid = {};

    public:
        card_channel() = default;

        explicit card_channel(std::shared_ptr<pn532::controller> ctrl) {
            _ctrl = std::move(ctrl);
        }

        card_channel(card_channel &&) noexcept = default;
        card_channel &operator=(card_channel &&) noexcept = default;


        ~card_channel() {
            if (_ctrl) {
                if (_pcd) {
                    _ctrl->initiator_release(_pcd->target_logical_index());
                }
                // Turn RF off
                _ctrl->rf_configuration_field(false, false);
            }
        }

        [[nodiscard]] pn532::result<> scan() {
            if (_ctrl == nullptr) {
                return pn532::channel_error::app_error;
            }
            TRY(_ctrl->rf_configuration_field(false, true));
            ESP_LOGI(TAG, "Bring forward a member card...");
            TRY_RESULT(_ctrl->initiator_list_passive_kbps106_typea(1)) {
                if (r->size() != 1) {
                    ESP_LOGW(TAG, "Place only one token within the field.");
                    return pn532::channel_error::hw_error;
                }
                const auto nfcid_s = mlab::data_to_hex_string(r->front().nfcid);
                ESP_LOGI(TAG, "Found a %s tag with NFC id %s", to_string(pn532::target_type::passive_106kbps_iso_iec_14443_4_typea), nfcid_s.c_str());
                _tkid = id_from_nfc_id(r->front().nfcid);
                _tag = std::make_unique<desfire::tag>(desfire::tag::make<desfire::esp32::default_cipher_provider>(*_ctrl, r->front().logical_index));
            }
            return mlab::result_success;
        }

        [[nodiscard]] explicit operator bool() const {
            return _tag != nullptr;
        }

        [[nodiscard]] desfire::tag &tag() {
            assert(_tag != nullptr);
            return *_tag;
        }

        [[nodiscard]] desfire::tag const &tag() const {
            assert(_tag != nullptr);
            return *_tag;
        }

        [[nodiscard]] token_id const &id() const {
            return _tkid;
        }
    };

    class keymaker::gate_channel {
        std::shared_ptr<pn532::controller> _ctrl = {};
        std::unique_ptr<pn532::p2p::pn532_target> _raw_target = {};
        std::unique_ptr<p2p::secure_target> _sec_target = {};
        std::unique_ptr<p2p::remote_gate_base> _remote_gate = {};
        unsigned _remote_proto_version = std::numeric_limits<unsigned>::max();
        unsigned _active_proto_version = std::numeric_limits<unsigned>::max();

    public:
        gate_channel() = default;

        explicit gate_channel(std::shared_ptr<pn532::controller> ctrl) {
            _ctrl = std::move(ctrl);
            if (_ctrl) {
                _raw_target = std::make_unique<pn532::p2p::pn532_target>(*_ctrl);
            }
        }

        [[nodiscard]] pub_key peer_pub_key() const {
            if (_sec_target) {
                return _sec_target->peer_pub_key();
            }
            return {};
        }

        gate_channel(gate_channel &&) noexcept = default;
        gate_channel &operator=(gate_channel &&) noexcept = default;

        ~gate_channel() {
            if (_remote_gate != nullptr) {
                _remote_gate->bye();
            }
            if (_ctrl != nullptr) {
                // Turn RF off
                _ctrl->rf_configuration_field(false, false);
            }
        }

        [[nodiscard]] p2p::r<> connect(key_pair const &kp) {
            if (_raw_target == nullptr) {
                return p2p::error::invalid;
            }
            std::array<std::uint8_t, 5> nfcid_data{};
            std::copy_n(std::begin(kp.raw_pk()), nfcid_data.size(), std::begin(nfcid_data));
            if (const auto r_rf_on = _ctrl->rf_configuration_field(false, true); not r_rf_on) {
                return p2p::channel_error_to_p2p_error(r_rf_on.error());
            }
            if (const auto r_init = _raw_target->init_as_dep_target(nfcid_data); r_init) {
                _sec_target = std::make_unique<p2p::secure_target>(*_raw_target, kp);
                if (const auto r_hshake = _sec_target->handshake(); r_hshake) {
                    const auto pk_s = mlab::data_to_hex_string(_sec_target->peer_pub_key().raw_pk());
                    ESP_LOGI(TAG, "Connected to peer with public key %s", pk_s.c_str());
                    // Try build a remote_channel
                    _remote_gate = std::make_unique<p2p::remote_gate_base>(*_sec_target);
                    if (const auto r_hello = _remote_gate->hello(); r_hello) {
                        const auto fw_s = r_hello->to_string();
                        ESP_LOGI(TAG, "Peer is gate running %s", fw_s.c_str());
                        ESP_LOGI(TAG, "Peer implements protocol version %u.", r_hello->proto_version);
                        _remote_proto_version = r_hello->proto_version;
                        switch (_remote_proto_version) {
                            case 0:
                                _remote_gate = std::make_unique<p2p::v0::remote_gate>(*_sec_target);
                                break;
                            default:
                                ESP_LOGW(TAG, "Unsupported gate protocol version %u.", _remote_proto_version);
                                return mlab::result_success;
                        }
                        _active_proto_version = _remote_proto_version;
                        ESP_LOGI(TAG, "Connected over gate protocol %u.", _active_proto_version);
                        return mlab::result_success;
                    } else {
                        ESP_LOGE(TAG, "Peer is not a gate.");
                        _remote_gate->bye();
                        _remote_gate = nullptr;
                        _sec_target = nullptr;
                        return r_hello.error();
                    }
                } else {
                    // Delete
                    _sec_target = nullptr;
                    return p2p::channel_error_to_p2p_error(r_hshake.error());
                }
            } else {
                return p2p::channel_error_to_p2p_error(r_init.error());
            }
        }

        [[nodiscard]] explicit operator bool() const {
            return _raw_target != nullptr and _sec_target != nullptr and _remote_gate != nullptr;
        }

        [[nodiscard]] unsigned active_proto_version() const {
            return _active_proto_version;
        }


        [[nodiscard]] unsigned remote_proto_version() const {
            return _remote_proto_version;
        }

        [[nodiscard]] p2p::remote_gate_base &remote_gate() {
            assert(_remote_gate != nullptr);
            return *_remote_gate;
        }

        [[nodiscard]] p2p::remote_gate_base const &remote_gate() const {
            assert(_remote_gate != nullptr);
            return *_remote_gate;
        }

        template <p2p::remote_gate_protocol Proto = p2p::remote_gate_base>
        [[nodiscard]] p2p::r<std::reference_wrapper<Proto const>> remote_gate() const {
            if (not *this) {
                ESP_LOGE(TAG, "You should check that the channel is open first.");
                return p2p::error::invalid;
            }
            if constexpr (std::is_same_v<Proto, p2p::remote_gate_base>) {
                return *_remote_gate;
            } else if constexpr (std::is_same_v<Proto, p2p::v0::remote_gate>) {
                if (active_proto_version() == 0) {
                    return std::cref(reinterpret_cast<Proto const &>(*_remote_gate));
                }
            }
            ESP_LOGE(TAG, "You should make sure this version of the protocol is supported!");
            return p2p::error::invalid;
        }

        template <p2p::remote_gate_protocol Proto = p2p::remote_gate_base>
        [[nodiscard]] p2p::r<std::reference_wrapper<Proto>> remote_gate() {
            TRY_RESULT(static_cast<gate_channel const *>(this)->remote_gate<Proto>()) {
                return std::ref(const_cast<Proto &>(r->get()));
            }
        }
    };

    p2p::r<keymaker::gate_channel> keymaker::open_gate_channel() const {
        if (not _ctrl) {
            ESP_LOGE(TAG, "Unable to communicate without a PN532 connected.");
            std::abort();
        }
        gate_channel chn{_ctrl};
        if (const auto r = chn.connect(keys()); r) {
            return chn;
        } else {
            return r.error();
        }
    }

    desfire::result<keymaker::card_channel> keymaker::open_card_channel() const {
        if (not _ctrl) {
            ESP_LOGE(TAG, "Unable to communicate without a PN532 connected.");
            std::abort();
        }
        card_channel chn{_ctrl};
        if (const auto r = chn.scan(); r) {
            return chn;
        } else {
            return desfire::error::controller_error;
        }
    }

    p2p::r<> keymaker::configure_gate_internal(keymaker_gate_data &gd) {
        TRY_RESULT_AS(open_gate_channel(), r_chn) {
            TRY_RESULT_AS(r_chn->remote_gate<p2p::v0::remote_gate>(), r_rg) {
                TRY_RESULT_AS(check_if_detected_gate_is_ours(r_rg->get()), r_ours) {
                    if (r_ours->first != std::numeric_limits<gate_id>::max()) {
                        if (not r_ours->second) {
                            ESP_LOGE(TAG, "Cannot configure a gate that is not ours.");
                        } else if (gd.pk != r_chn->peer_pub_key()) {
                            if (gd.status == gate_status::configured or gd.status == gate_status::deleted) {
                                ESP_LOGE(TAG, "The locally stored public key does not match the remote, reset this gate.");
                            }
                        } else {
                            ESP_LOGE(TAG, "This gate is already configured.");
                        }
                        return p2p::error::invalid;
                    }
                }
                TRY_RESULT(r_rg->get().register_gate(gd.id)) {
                    gd.pk = r_chn->peer_pub_key();
                    gd.bk = *r;
                    gd.status = gate_status::configured;
                    if (not save_gate(_gates.back())) {
                        return p2p::error::invalid;
                    }
                }
            }
        }
        return mlab::result_success;
    }

    p2p::r<gate_id> keymaker::gate_add(std::string notes, bool configure) {
        const gate_id id{_gates.size()};
        _gates.push_back(keymaker_gate_data{id, {}, {}, gate_status::initialized, std::move(notes)});
        if (configure) {
            ESP_LOGI(TAG, "Bring closer an unconfigured gate...");
            if (const auto r = configure_gate_internal(_gates.back()); r) {
                ESP_LOGI(TAG, "Gate configured.");
            } else {
                _gates.pop_back();
                ESP_LOGE(TAG, "Unable to configure gate.");
                return r.error();
            }
        } else {
            if (not save_gate(_gates.back())) {
                return p2p::error::invalid;
            }
            ESP_LOGI(TAG, "Gate registered but not configured.");
            ESP_LOGW(TAG, "Run gate-configure --gate-id %lu", std::uint32_t{id});
        }
        return id;
    }

    p2p::r<> keymaker::gate_configure(gate_id id, bool force) {
        if (std::uint32_t{id} >= _gates.size()) {
            ESP_LOGE(TAG, "Gate %lu not found.", std::uint32_t{id});
            return p2p::error::arg_error;
        }
        auto &gd = _gates[std::uint32_t{id}];
        if (gd.status != gate_status::initialized) {
            ESP_LOG_LEVEL((force ? ESP_LOG_WARN : ESP_LOG_ERROR), TAG, "Gate status is %s.", to_string(gd.status));
            if (not force) {
                return p2p::error::invalid;
            }
        }
        ESP_LOGI(TAG, "Bring closer an unconfigured gate...");
        if (const auto r = configure_gate_internal(gd); r) {
            ESP_LOGI(TAG, "Gate configured.");
            return mlab::result_success;
        } else {
            return r.error();
        }
    }

    p2p::r<> keymaker::gate_remove(gate_id id, bool force) {
        if (std::uint32_t{id} >= _gates.size()) {
            ESP_LOGE(TAG, "Gate %lu not found.", std::uint32_t{id});
            return p2p::error::arg_error;
        }
        auto &gd = _gates[std::uint32_t{id}];
        if (gd.status == gate_status::initialized) {
            ESP_LOGW(TAG, "The gate was never configured!");
            gd.status = gate_status::deleted;
            if (not save_gate(gd)) {
                return p2p::error::invalid;
            }
        }
        if (gd.status == gate_status::deleted) {
            ESP_LOGW(TAG, "The gate was already deleted.");
            if (not force) {
                return mlab::result_success;
            }
        }
        auto pk_s = mlab::data_to_hex_string(gd.pk.raw_pk());
        ESP_LOGI(TAG, "Bring closer a gate with public key %s...", pk_s.c_str());
        auto open_and_reset = [&]() -> p2p::r<> {
            TRY_RESULT_AS(open_gate_channel(), r_chn) {
                TRY_RESULT_AS(r_chn->remote_gate<p2p::v0::remote_gate>(), r_rg) {
                    if (r_chn->peer_pub_key() != gd.pk) {
                        ESP_LOGE(TAG, "This is not gate %lu, has a different public key.", std::uint32_t{id});
                        return p2p::error::invalid;
                    }
                    TRY_RESULT_AS(check_if_detected_gate_is_ours(r_rg->get()), r_ours) {
                        if (r_ours->first == std::numeric_limits<gate_id>::max()) {
                            ESP_LOGW(TAG, "This gate is not configured or was already deleted.");
                            return mlab::result_success;
                        } else if (not r_ours->second) {
                            ESP_LOGE(TAG, "This gate is not ours.");
                            return p2p::error::invalid;
                        } else if (r_ours->first != id) {
                            ESP_LOGE(TAG, "This is not gate %lu, it's gate %lu.", std::uint32_t{id}, std::uint32_t{r_ours->first});
                            return p2p::error::invalid;
                        }
                    }
                    TRY(r_rg->get().reset_gate());
                }
            }
            return mlab::result_success;
        };
        if (const auto r = open_and_reset(); r) {
            gd.status = gate_status::deleted;
            if (not save_gate(gd)) {
                return p2p::error::invalid;
            }
            return mlab::result_success;
        } else {
            if (force) {
                ESP_LOGW(TAG, "The gate was not found or could not be reset, but we will force-delete it.");
                gd.status = gate_status::deleted;
                if (not save_gate(gd)) {
                    return p2p::error::invalid;
                }
            } else {
                ESP_LOGE(TAG, "The gate was not found or could not be reset.");
            }
            return r.error();
        }
    }

    void keymaker::gate_set_notes(gate_id id, std::string notes) {
        if (std::uint32_t{id} >= _gates.size()) {
            ESP_LOGE(TAG, "Gate not found.");
            return;
        }
        auto &gd = _gates[std::uint32_t{id}];
        gd.notes = std::move(notes);
        save_gate(gd);
    }

    gate_status keymaker::gate_get_status(gate_id id) const {
        if (std::uint32_t{id} >= _gates.size()) {
            ESP_LOGE(TAG, "Gate not found.");
            return gate_status::unknown;
        }
        return _gates[std::uint32_t{id}].status;
    }

    nvs::r<> keymaker::save_gate(keymaker_gate_data const &gd) {
        if (_gate_ns) {
            TRY(gd.save_to(*_gate_ns));
        }
        return mlab::result_success;
    }

    p2p::r<gate_id, bool> keymaker::check_if_detected_gate_is_ours(p2p::v0::remote_gate &rg) const {
        gate_id gid = std::numeric_limits<gate_id>::max();
        bool ours = false;
        TRY_RESULT(rg.get_registration_info()) {
            if (r->id != std::numeric_limits<gate_id>::max()) {
                gid = r->id;
                ours = r->keymaker_pk == keys();
                ESP_LOGI(TAG, "This gate is configured as gate %lu with %s keymaker.",
                         std::uint32_t{r->id}, ours ? "this" : "another");
            } else {
                ESP_LOGI(TAG, "This gate is not configured.");
            }
        }
        return {gid, ours};
    }

    p2p::r<p2p::v0::update_config> keymaker::gate_get_update_config() {
        ESP_LOGI(TAG, "Bring closer a gate...");
        TRY_RESULT_AS(open_gate_channel(), r_chn) {
            TRY_RESULT_AS(r_chn->remote_gate<p2p::v0::remote_gate>(), r_rg) {
                TRY(check_if_detected_gate_is_ours(r_rg->get()));
                TRY_RESULT(r_rg->get().get_update_settings()) {
                    return std::move(*r);
                }
            }
        }
    }

    p2p::r<p2p::v0::wifi_status> keymaker::gate_get_wifi_status() {
        ESP_LOGI(TAG, "Bring closer a gate...");
        TRY_RESULT_AS(open_gate_channel(), r_chn) {
            TRY_RESULT_AS(r_chn->remote_gate<p2p::v0::remote_gate>(), r_rg) {
                TRY(check_if_detected_gate_is_ours(r_rg->get()));
                TRY_RESULT(r_rg->get().get_wifi_status()) {
                    return std::move(*r);
                }
            }
        }
    }

    p2p::r<> keymaker::gate_set_update_config(std::string_view update_channel, bool automatic_updates) {
        ESP_LOGI(TAG, "Bring closer a gate...");
        TRY_RESULT_AS(open_gate_channel(), r_chn) {
            TRY_RESULT_AS(r_chn->remote_gate<p2p::v0::remote_gate>(), r_rg) {
                TRY(check_if_detected_gate_is_ours(r_rg->get()));
                TRY(r_rg->get().set_update_settings(update_channel, automatic_updates));
            }
        }
        return mlab::result_success;
    }

    p2p::r<bool> keymaker::gate_connect_wifi(std::string_view ssid, std::string_view password) {
        ESP_LOGI(TAG, "Bring closer a gate...");
        TRY_RESULT_AS(open_gate_channel(), r_chn) {
            TRY_RESULT_AS(r_chn->remote_gate<p2p::v0::remote_gate>(), r_rg) {
                TRY(check_if_detected_gate_is_ours(r_rg->get()));
                TRY_RESULT(r_rg->get().connect_wifi(ssid, password)) {
                    if (not *r) {
                        ESP_LOGW(TAG, "Wifi did not connect within the given timespan.");
                    }
                    return r;
                }
            }
        }
    }

    p2p::r<keymaker_gate_info> keymaker::gate_inspect(gate_id id) const {
        std::optional<pub_key> exp_pk = std::nullopt;
        bool ours = true;
        if (id == std::numeric_limits<gate_id>::max()) {
            ESP_LOGI(TAG, "Bring closer a gate...");
            TRY_RESULT_AS(open_gate_channel(), r_chn) {
                exp_pk = r_chn->peer_pub_key();
                TRY_RESULT_AS(r_chn->remote_gate<p2p::v0::remote_gate>(), r_rg) {
                    TRY_RESULT_AS(check_if_detected_gate_is_ours(r_rg->get()), r_ours) {
                        if (r_ours->first != std::numeric_limits<gate_id>::max()) {
                            id = r_ours->first;
                            ours = r_ours->second;
                        }
                    }
                }
            }
        }
        if (id == std::numeric_limits<gate_id>::max()) {
            return p2p::error::p2p_app_error;
        }
        if (not ours) {
            return keymaker_gate_info{id, *exp_pk, gate_status::unknown, {}};
        }
        if (std::uint32_t{id} >= _gates.size()) {
            ESP_LOGE(TAG, "Gate not found.");
            return p2p::error::arg_error;
        }
        auto const &gd = _gates[std::uint32_t{id}];
        if (exp_pk and *exp_pk != gd.pk) {
            ESP_LOGE(TAG, "Mismatching stored public key and remote public key.");
        }
        return keymaker_gate_info{gd.id, gd.pk, gd.status, gd.notes};
    }

    namespace cmd {
        template <>
        struct parser<keymaker_gate_info> {
            [[nodiscard]] static std::string to_string(keymaker_gate_info const &gi) {
                if (gi.status == gate_status::configured) {
                    return mlab::concatenate({"Gate ", std::to_string(std::uint32_t{gi.id}), "\n",
                                              "Configured, PK ", mlab::data_to_hex_string(gi.pk.raw_pk()), "\n",
                                              "Notes: ", gi.notes.empty() ? "n/a" : gi.notes});
                } else {
                    return mlab::concatenate({"Gate ", std::to_string(std::uint32_t{gi.id}), "\n",
                                              "Status ", ka::to_string(gi.status),
                                              ".\nNotes: ", gi.notes.empty() ? "n/a" : gi.notes});
                }
            }
        };
        template <>
        struct parser<gate_status> {
            [[nodiscard]] static std::string to_string(gate_status gs) {
                return ka::to_string(gs);
            }
        };
        template <class T>
        struct parser<desfire::result<T>> {
            [[nodiscard]] static std::string to_string(desfire::result<T> const &r) {
                if (r) {
                    return parser<T>::to_string(*r);
                } else {
                    return member_token::describe(r.error());
                }
            }
        };
        template <class T>
        struct parser<p2p::r<T>> {
            [[nodiscard]] static std::string to_string(p2p::r<T> const &r) {
                if (r) {
                    return parser<T>::to_string(*r);
                } else {
                    return ka::p2p::to_string(r.error());
                }
            }
        };
        template <>
        struct parser<p2p::r<>> {
            [[nodiscard]] static std::string to_string(p2p::r<> const &r) {
                if (r) {
                    return "success";
                } else {
                    return ka::p2p::to_string(r.error());
                }
            }
        };
        template <>
        struct parser<desfire::result<>> {
            [[nodiscard]] static std::string to_string(desfire::result<> const &r) {
                if (r) {
                    return "success";
                } else {
                    return member_token::describe(r.error());
                }
            }
        };
        template <>
        struct parser<gate_id> {
            [[nodiscard]] static std::string to_string(gate_id gid) {
                if (gid == std::numeric_limits<gate_id>::max()) {
                    return "gate_id: invalid";
                }
                return mlab::concatenate({"gate-id: ", parser<std::uint32_t>::to_string(std::uint32_t{gid})});
            }
            [[nodiscard]] static std::string type_description() {
                return "gate-id";
            }

            [[nodiscard]] static ka::cmd::r<gate_id> parse(std::string_view s) {
                if (const auto r = parser<std::uint32_t>::parse(s); r) {
                    return gate_id{*r};
                } else {
                    return r.error();
                }
            }
        };

        template <>
        struct parser<p2p::v0::update_config> {
            [[nodiscard]] static std::string to_string(p2p::v0::update_config const &us) {
                return mlab::concatenate({us.enable_automatic_update ? "automatic, from " : "not automatic, from ",
                                          us.update_channel});
            }
        };
        template <>
        struct parser<p2p::v0::wifi_status> {
            [[nodiscard]] static std::string to_string(p2p::v0::wifi_status const &ws) {
                if (ws.ssid.empty()) {
                    return "not associated";
                }
                return mlab::concatenate({"associated to ", ws.ssid,
                                          ws.operational ? ", operational" : ", not operational"});
            }
        };
        template <>
        struct parser<ka::identity> {
            [[nodiscard]] static std::string to_string(ka::identity const &id) {
                return mlab::concatenate({" token id: ", mlab::data_to_hex_string(id.id), "\n",
                                          "   holder: ", id.holder, "\n",
                                          "publisher: ", id.publisher});
            }
        };
        template <>
        struct parser<desfire::cipher_type> {
            [[nodiscard]] static std::string to_string(desfire::cipher_type ct) {
                switch (ct) {
                    case desfire::cipher_type::aes128:
                        return "aes";
                    case desfire::cipher_type::des:
                        return "des";
                    case desfire::cipher_type::des3_2k:
                        return "3des2k";
                    case desfire::cipher_type::des3_3k:
                        return "3des";
                    case desfire::cipher_type::none:
                        return "none";
                    default:
                        return "invalid";
                }
            }

            [[nodiscard]] static ka::cmd::r<desfire::cipher_type> parse(std::string_view s) {
                std::string lc_s{s};
                std::transform(std::begin(lc_s), std::end(lc_s), std::begin(lc_s), ::tolower);
                if (lc_s == "aes") {
                    return desfire::cipher_type::aes128;
                } else if (lc_s == "des") {
                    return desfire::cipher_type::des;
                } else if (lc_s == "3des2k") {
                    return desfire::cipher_type::des3_2k;
                } else if (lc_s == "3des") {
                    return desfire::cipher_type::des3_3k;
                } else if (lc_s == "none") {
                    return desfire::cipher_type::none;
                } else {
                    return ka::cmd::error::parse;
                }
            }
        };
        template <>
        struct parser<desfire::any_key> {
            [[nodiscard]] static std::string to_string(desfire::any_key const &k) {
                if (k.type() == desfire::cipher_type::none) {
                    return "auto";
                }
                auto body = k.get_packed_key_body();
                auto first_nonzero = std::find_if(std::begin(body), std::end(body), [](auto b) { return b != 0; });
                if (first_nonzero == std::end(body) and first_nonzero != std::begin(body)) {
                    // If it's all zeroes, make sure there is at least one printed
                    --first_nonzero;
                }
                return mlab::concatenate({parser<desfire::cipher_type>::to_string(k.type()), ":", mlab::data_to_hex_string(first_nonzero, std::end(body))});
            }

            [[nodiscard]] static std::string type_description() {
                return "auto|(aes|des|3des2k|3des:<hex key>)";
            }

            [[nodiscard]] static ka::cmd::r<desfire::any_key> parse(std::string_view s) {
                auto parse_internal = [&]() -> std::optional<desfire::any_key> {
                    const auto colon_pos = s.find_first_of(':');
                    auto opt_ct = parser<desfire::cipher_type>::parse(s.substr(0, colon_pos));
                    if (not opt_ct) {
                        return std::nullopt;
                    } else if (colon_pos == std::string_view::npos) {
                        return desfire::any_key{*opt_ct};
                    }
                    auto hex_str = std::string{s.substr(colon_pos + 1)};
                    if (hex_str.size() % 2 != 0) {
                        hex_str.insert(std::begin(hex_str), '0');
                    }
                    auto body = mlab::data_from_hex_string(hex_str);
                    bool matches_size = true;
                    auto pad_body = [&](std::size_t sz) {
                        if (body.size() > sz) {
                            matches_size = false;
                            return;
                        }
                        body.insert(std::begin(body), sz - body.size(), 0);
                    };
                    switch (*opt_ct) {
                        case desfire::cipher_type::des:
                            pad_body(desfire::key<desfire::cipher_type::des>::size);
                            break;
                        case desfire::cipher_type::des3_2k:
                            pad_body(desfire::key<desfire::cipher_type::des3_2k>::size);
                            break;
                        case desfire::cipher_type::des3_3k:
                            pad_body(desfire::key<desfire::cipher_type::des3_3k>::size);
                            break;
                        case desfire::cipher_type::aes128:
                            pad_body(desfire::key<desfire::cipher_type::aes128>::size);
                            break;
                        default:
                            break;
                    }
                    if (not matches_size) {
                        return std::nullopt;
                    }
                    return desfire::any_key(*opt_ct, body.data_view());
                };
                if (const auto opt_k = parse_internal(); opt_k) {
                    return *opt_k;
                } else {
                    ESP_LOGW(TAG, "Keys must be auto or in the format <cipher type>:<hex string>, where cipher type is aes|des|3des2k|3des.");
                    return cmd::error::parse;
                }
            }
        };

        template <>
        struct parser<std::vector<keymaker_gate_info>> {
            [[nodiscard]] static std::string to_string(std::vector<keymaker_gate_info> const &gis) {
                if (gis.empty()) {
                    return "(none)";
                }
                std::vector<std::string> pieces;
                pieces.reserve(gis.size());
                for (std::size_t i = 0; i < gis.size(); ++i) {
                    auto const &g = gis[i];
                    pieces.emplace_back(mlab::concatenate({i < 9 ? " " : "", std::to_string(i + 1),
                                                           ". Gate ", std::to_string(std::uint32_t{g.id}), " (", ka::to_string(g.status),
                                                           g.status != gate_status::configured ? ")" : ") PK: ",
                                                           g.status != gate_status::configured ? "" : mlab::data_to_hex_string(g.pk.raw_pk())}));
                }
                return mlab::concatenate_s(pieces, "\n");
            }
        };
    }// namespace cmd

    std::vector<keymaker_gate_info> keymaker::gate_list() const {
        std::vector<keymaker_gate_info> retval;
        retval.reserve(_gates.size());
        std::copy(std::begin(_gates), std::end(_gates), std::back_inserter(retval));
        return retval;
    }

    r<> keymaker::card_format(desfire::any_key root_key, desfire::any_key new_root_key) {
        TRY_RESULT(open_card_channel()) {
            if (root_key.type() == desfire::cipher_type::none) {
                ESP_LOGI(TAG, "Using token-specific key to unlock the card.");
                root_key = keys().derive_token_root_key(r->id());
            }
            TRY(r->tag().select_application());
            TRY(r->tag().authenticate(root_key));
            if (new_root_key.type() == desfire::cipher_type::none) {
                ESP_LOGI(TAG, "Using token-specific key as a new key.");
                new_root_key = keys().derive_token_root_key(r->id());
            }
            ESP_LOGI(TAG, "Changing root key...");
            const auto default_k = desfire::key<desfire::cipher_type::des>{};
            TRY(r->tag().change_key(default_k));
            TRY(r->tag().select_application());
            TRY(r->tag().authenticate(default_k));
            ESP_LOGW(TAG, "We will now format this card.");
            for (int i = 5; i > 0; --i) {
                ESP_LOGW(TAG, "Formatting in %d...", i);
                std::this_thread::sleep_for(1s);
            }
            return r->tag().format_picc();
        }
    }

    r<> keymaker::card_deploy(desfire::any_key old_root_key, std::string_view holder, std::string_view publisher) {
        TRY_RESULT(open_card_channel()) {
            if (old_root_key.type() == desfire::cipher_type::none) {
                ESP_LOGI(TAG, "Using token-specific key to unlock the card.");
                old_root_key = keys().derive_token_root_key(r->id());
            }
            member_token tkn{r->tag()};
            TRY(tkn.deploy(keys(), identity{r->id(), std::string{holder}, std::string{publisher}}));
            return mlab::result_success;
        }
    }

    r<> keymaker::card_enroll_gate(gate_id gid, std::string_view holder, std::string_view publisher) {
        if (std::uint32_t{gid} >= _gates.size()) {
            ESP_LOGE(TAG, "Gate not found.");
            return desfire::error::parameter_error;
        } else if (_gates[std::uint32_t{gid}].status != gate_status::configured) {
            ESP_LOGE(TAG, "Gate not configured.");
            return desfire::error::parameter_error;
        }
        TRY_RESULT(open_card_channel()) {
            member_token tkn{r->tag()};
            TRY(tkn.enroll_gate(keys(), _gates[std::uint32_t{gid}], identity{r->id(), std::string{holder}, std::string{publisher}}));
            return mlab::result_success;
        }
    }

    r<> keymaker::card_unenroll_gate(gate_id gid) {
        if (std::uint32_t{gid} >= _gates.size()) {
            ESP_LOGW(TAG, "Gate not found, but will attempt nonetheless.");
            ESP_LOGW(TAG, "A different master key protects gates enrolled by other keymakers.");
        }
        TRY_RESULT(open_card_channel()) {
            member_token tkn{r->tag()};
            TRY(tkn.unenroll_gate(keys(), _gates[std::uint32_t{gid}]));
            return mlab::result_success;
        }
    }

    r<bool> keymaker::card_is_gate_enrolled(gate_id gid) const {
        TRY_RESULT(open_card_channel()) {
            member_token tkn{r->tag()};
            TRY_RESULT_AS(tkn.is_gate_enrolled(gid, true, true), r_enrolled) {
                if (not *r_enrolled) {
                    return false;
                }
            }
            if (std::uint32_t{gid} >= _gates.size()) {
                ESP_LOGW(TAG, "Gate not found, so we cannot confirm the authenticity.");
                return true;
            }
            TRY_RESULT_AS(tkn.is_gate_enrolled_correctly(keys(), _gates[std::uint32_t{gid}]), r_enrolled) {
                return r_enrolled->first;
            }
        }
    }

    r<> keymaker::card_is_deployed() const {
        TRY_RESULT(open_card_channel()) {
            member_token tkn{r->tag()};
            return tkn.is_deployed_correctly(keys());
        }
    }

    r<identity> keymaker::card_get_identity() const {
        TRY_RESULT(open_card_channel()) {
            member_token tkn{r->tag()};
            return tkn.read_encrypted_master_file(keys(), true, true);
        }
    }

    r<std::vector<keymaker_gate_info>> keymaker::card_list_enrolled_gates() const {
        TRY_RESULT(open_card_channel()) {
            member_token tkn{r->tag()};
            TRY_RESULT_AS(tkn.list_gates(true, true), r_gates) {
                std::vector<keymaker_gate_info> gi{};
                gi.reserve(r_gates->size());
                for (auto gid : *r_gates) {
                    if (std::uint32_t{gid} >= _gates.size()) {
                        ESP_LOGW(TAG, "Unknown enrolled gate %lu.", std::uint32_t{gid});
                    } else {
                        gi.emplace_back(_gates[std::uint32_t{gid}]);
                    }
                }
                return gi;
            }
        }
    }

    r<desfire::any_key> keymaker::card_recover_root_key(desfire::any_key test_root_key) const {
        ESP_LOGI(TAG, "Attempting to recover root key...");
        static constexpr std::uint8_t secondary_keys_version = 0x10;
        static constexpr std::array<std::uint8_t, 8> secondary_des_key = {0x0, 0x2, 0x4, 0x6, 0x8, 0xa, 0xc, 0xe};
        static constexpr std::array<std::uint8_t, 16> secondary_des3_2k_key = {0x0, 0x2, 0x4, 0x6, 0x8, 0xa, 0xc, 0xe, 0x10, 0x12, 0x14, 0x16, 0x18, 0x1a, 0x1c, 0x1e};
        static constexpr std::array<std::uint8_t, 24> secondary_des3_3k_key = {0x0, 0x2, 0x4, 0x6, 0x8, 0xa, 0xc, 0xe, 0x10, 0x12, 0x14, 0x16, 0x18, 0x1a, 0x1c, 0x1e, 0x20, 0x22, 0x24, 0x26, 0x28, 0x2a, 0x2c, 0x2e};
        static constexpr std::array<std::uint8_t, 16> secondary_aes_key = {0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0xa, 0xb, 0xc, 0xd, 0xe, 0xf};
        static key_pair test_kp{{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
                                 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f}};
        static key_pair demo_kp{ka::pwhash, "foobar"};
        TRY_RESULT(open_card_channel()) {
            const std::array<desfire::any_key, 12> keys_to_test = {
                    desfire::any_key{desfire::cipher_type::des},
                    std::move(test_root_key),
                    keys().derive_token_root_key(r->id()),
                    test_kp.derive_token_root_key(r->id()),
                    demo_kp.derive_token_root_key(r->id()),
                    desfire::any_key{desfire::cipher_type::des3_2k},
                    desfire::any_key{desfire::cipher_type::des3_3k},
                    desfire::any_key{desfire::cipher_type::aes128},
                    desfire::any_key{desfire::cipher_type::des, mlab::make_range(secondary_des_key), 0, secondary_keys_version},
                    desfire::any_key{desfire::cipher_type::des3_2k, mlab::make_range(secondary_des3_2k_key), 0, secondary_keys_version},
                    desfire::any_key{desfire::cipher_type::des3_3k, mlab::make_range(secondary_des3_3k_key), 0, secondary_keys_version},
                    desfire::any_key{desfire::cipher_type::aes128, mlab::make_range(secondary_aes_key), 0, secondary_keys_version}};
            TRY(r->tag().select_application());
            auto suppress = desfire::esp32::suppress_log{DESFIRE_LOG_PREFIX};
            for (auto const &key : keys_to_test) {
                if (key.type() != desfire::cipher_type::none and r->tag().authenticate(key)) {
                    return key;
                }
            }
            ESP_LOGW(TAG, "Unable to find root key.");
            return desfire::error::authentication_error;
        }
    }

    void keymaker::register_commands(ka::cmd::shell &sh) {
        device::register_commands(sh);
        sh.register_command("gate-configure", *this, &keymaker::gate_configure, {{"gate-id", "gid"}, cmd::flag{"force", false}});
        sh.register_command("gate-remove", *this, &keymaker::gate_remove, {{"gate-id", "gid"}, cmd::flag{"force", false}});
        sh.register_command("gate-add", *this, &keymaker::gate_add, {{"notes", {}, ""}, cmd::flag{"configure", true}});
        sh.register_command("gate-inspect", *this, &keymaker::gate_inspect, {{"gate-id", "gid", std::numeric_limits<gate_id>::max()}});
        sh.register_command("gate-set-notes", *this, &keymaker::gate_set_notes, {{"gate-id", "gid"}, {"notes"}});
        sh.register_command("gate-get-status", *this, &keymaker::gate_get_status, {{"gate-id", "gid"}});
        sh.register_command("gate-wifi-get-status", *this, &keymaker::gate_get_wifi_status, {});
        sh.register_command("gate-wifi-connect", *this, &keymaker::gate_connect_wifi, {{"ssid"}, {"password"}});
        sh.register_command("gate-update-get-config", *this, &keymaker::gate_get_update_config, {});
        sh.register_command("gate-update-set-config", *this, &keymaker::gate_set_update_config,
                            {{"update-channel", std::optional<std::string>{""}}, cmd::flag{"auto", true}});
        sh.register_command("gate-list", *this, &keymaker::gate_list, {});
        sh.register_command("card-recover-root-key", *this, &keymaker::card_recover_root_key,
                            {{"test-key", desfire::any_key{desfire::cipher_type::none}}});
        sh.register_command("card-format", *this, &keymaker::card_format,
                            {{"old-key", desfire::any_key{desfire::cipher_type::des}}, {"new-key", desfire::any_key{desfire::cipher_type::des}}});
        sh.register_command("card-deploy", *this, &keymaker::card_deploy,
                            {{"old-key", desfire::any_key{desfire::cipher_type::none}}, {"holder"}, {"publisher"}});
        sh.register_command("card-gate-enroll", *this, &keymaker::card_enroll_gate,
                            {{"gate-id", "gid"}, {"holder"}, {"publisher"}});
        sh.register_command("card-gate-unenroll", *this, &keymaker::card_unenroll_gate, {{"gate-id", "gid"}});
        sh.register_command("card-gate-is-enrolled", *this, &keymaker::card_is_gate_enrolled, {{"gate-id", "gid"}});
        sh.register_command("card-is-deployed", *this, &keymaker::card_is_deployed, {});
        sh.register_command("card-get-identity", *this, &keymaker::card_get_identity, {});
        sh.register_command("card-gate-list", *this, &keymaker::card_list_enrolled_gates, {});
    }


    nvs::r<> keymaker_gate_data::save_to(nvs::namespc &ns) const {
        TRY(ns.set_encode_blob(get_nvs_key(id), *this));
        TRY(ns.commit());
        return mlab::result_success;
    }

    std::string keymaker_gate_data::get_nvs_key(gate_id gid) {
        std::string buffer;
        buffer.resize(9);
        std::snprintf(buffer.data(), buffer.size(), "%08lx", std::uint32_t{gid});
        buffer.resize(8);
        return buffer;
    }

    nvs::r<keymaker_gate_data> keymaker_gate_data::load_from(nvs::const_namespc const &ns, gate_id gid) {
        return ns.get_parse_blob<keymaker_gate_data>(get_nvs_key(gid));
    }

    std::vector<keymaker_gate_data> keymaker_gate_data::load_from(nvs::const_namespc const &ns) {
        std::vector<keymaker_gate_data> retval;
        for (gate_id gid = std::numeric_limits<gate_id>::min(); gid < std::numeric_limits<gate_id>::max(); gid = gate_id{gid + 1}) {
            if (const auto r = load_from(ns, gid); r) {
                retval.push_back(*r);
            } else if (r.error() == nvs::error::not_found) {
                break;
            } else {
                ESP_LOGE(TAG, "Unable to load gate %lu, error %s", std::uint32_t{gid}, to_string(r.error()));
                retval.push_back(keymaker_gate_data{gid, {}, {}, gate_status::unknown, {}});
            }
        }
        return retval;
    }
}// namespace ka

namespace mlab {
    bin_data &operator<<(bin_data &bd, ka::keymaker_gate_data const &gd) {
        const auto sz = 4 + 1 + ka::raw_pub_key::array_size + ka::gate_base_key::array_size + 4 + gd.notes.size();
        return bd << prealloc(sz) << gd.id << gd.status << gd.pk << gd.bk << length_encoded << gd.notes;
    }

    bin_stream &operator>>(bin_stream &s, ka::keymaker_gate_data &gd) {
        if (s.remaining() < 4 + 1 + ka::raw_pub_key::array_size + ka::gate_base_key::array_size + 4) {
            s.set_bad();
            return s;
        }
        ka::keymaker_gate_data new_gd{};
        s >> new_gd.id >> new_gd.status >> new_gd.pk >> new_gd.bk >> length_encoded >> new_gd.notes;
        if (s.bad()) {
            return s;
        }
        gd = new_gd;
        return s;
    }

}// namespace mlab