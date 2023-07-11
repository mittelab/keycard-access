//
// Created by spak on 6/14/23.
//

#include <esp_log.h>
#include <ka/console.hpp>
#include <ka/keymaker.hpp>
#include <mlab/result_macro.hpp>
#include <mlab/strutils.hpp>

#define TAG "KEYM"

#undef MLAB_RESULT_LOG_PREFIX
#define MLAB_RESULT_LOG_PREFIX TAG

namespace ka {

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
            _gates = gate_data::load_from(*_gate_ns);
        }
    }

    keymaker::keymaker(key_pair kp)
        : device{kp} {}

    class keymaker::card_channel {
        std::shared_ptr<pn532::controller> _ctrl = {};
        std::shared_ptr<pn532::desfire_pcd> _pcd = {};
        std::unique_ptr<desfire::tag> _tag = {};
    public:
        card_channel() = default;

        explicit card_channel(std::shared_ptr<pn532::controller> ctrl) {
            _ctrl = std::move(ctrl);
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

    pn532::result<keymaker::card_channel> keymaker::open_card_channel() const {
        if (not _ctrl) {
            ESP_LOGE(TAG, "Unable to communicate without a PN532 connected.");
            std::abort();
        }
        card_channel chn{_ctrl};
        if (const auto r = chn.scan(); r) {
            return chn;
        } else {
            return r.error();
        }
    }

    p2p::r<> keymaker::configure_gate_internal(gate_data &gd) {
        TRY_RESULT_AS(open_gate_channel(), r_chn) {
            TRY_RESULT_AS(r_chn->remote_gate<p2p::v0::remote_gate>(), r_rg) {
                TRY_RESULT_AS(check_if_detected_gate_is_ours(r_rg->get()), r_ours) {
                    if (r_ours->first != std::numeric_limits<gate_id>::max()) {
                        if (not r_ours->second) {
                            ESP_LOGE(TAG, "Cannot configure a gate that is not ours.");
                        } else if (gd.gate_pub_key != r_chn->peer_pub_key()) {
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
                    gd.gate_pub_key = r_chn->peer_pub_key();
                    gd.app_base_key = *r;
                    gd.status = gate_status::configured;
                    if (not save_gate(_gates.back())) {
                        return p2p::error::invalid;
                    }
                }
            }
        }
        return mlab::result_success;
    }

    gate_id keymaker::register_gate(std::string notes, bool configure) {
        const gate_id id{_gates.size()};
        _gates.push_back(gate_data{id, std::move(notes), ka::gate_status::initialized, {}, {}});
        if (configure) {
            ESP_LOGI(TAG, "Bring closer an unconfigured gate...");
            if (configure_gate_internal(_gates.back())) {
                ESP_LOGI(TAG, "Gate configured.");
            } else {
                _gates.pop_back();
                ESP_LOGE(TAG, "Unable to configure gate.");
                return std::numeric_limits<gate_id>::max();
            }
        } else {
            save_gate(_gates.back());
            ESP_LOGI(TAG, "Gate registered but not configured.");
            ESP_LOGW(TAG, "Run gate-configure --gate-id %lu", std::uint32_t{id});
        }
        return id;
    }

    bool keymaker::configure_gate(ka::gate_id id, bool force) {
        if (std::uint32_t{id} >= _gates.size()) {
            ESP_LOGE(TAG, "Gate %lu not found.", std::uint32_t{id});
            return false;
        }
        auto &gd = _gates[std::uint32_t{id}];
        if (gd.status != gate_status::initialized) {
            ESP_LOG_LEVEL((force ? ESP_LOG_WARN : ESP_LOG_ERROR), TAG, "Gate status is %s.", to_string(gd.status));
            if (not force) {
                return false;
            }
        }
        ESP_LOGI(TAG, "Bring closer an unconfigured gate...");
        if (configure_gate_internal(gd)) {
            ESP_LOGI(TAG, "Gate configured.");
            return true;
        }
        return false;
    }

    bool keymaker::delete_gate(ka::gate_id id, bool force) {
        if (std::uint32_t{id} >= _gates.size()) {
            ESP_LOGE(TAG, "Gate %lu not found.", std::uint32_t{id});
            return false;
        }
        auto &gd = _gates[std::uint32_t{id}];
        if (gd.status == gate_status::initialized) {
            ESP_LOGW(TAG, "The gate was never configured!");
            gd.status = gate_status::deleted;
            return bool(save_gate(gd));
        }
        if (gd.status == gate_status::deleted) {
            ESP_LOGW(TAG, "The gate was already deleted.");
            if (not force) {
                return true;
            }
        }
        auto pk_s = mlab::data_to_hex_string(gd.gate_pub_key.raw_pk());
        ESP_LOGI(TAG, "Bring closer a gate with public key %s...", pk_s.c_str());
        auto open_and_reset = [&]() -> p2p::r<> {
            TRY_RESULT_AS(open_gate_channel(), r_chn) {
                TRY_RESULT_AS(r_chn->remote_gate<p2p::v0::remote_gate>(), r_rg) {
                    if (r_chn->peer_pub_key() != gd.gate_pub_key) {
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
        if (const auto r = open_and_reset(); not r) {
            if (force) {
                ESP_LOGW(TAG, "The gate was not found or could not be reset, but we will force-delete it.");
            } else {
                ESP_LOGE(TAG, "The gate was not found or could not be reset.");
                return false;
            }
        }
        gd.status = gate_status::deleted;
        return bool(save_gate(gd));
    }

    gate_data const *keymaker::operator[](gate_id id) const {
        const auto i = std::uint32_t(id);
        if (i < gates().size()) {
            return &gates()[i];
        }
        return nullptr;
    }

    void keymaker::set_gate_notes(gate_id id, std::string notes) {
        if (auto const *gd = (*this)[id]; gd != nullptr) {
            // Const-casting so we don't have to repeat the operator[] code.
            const_cast<gate_data *>(gd)->notes = std::move(notes);
            save_gate(*gd);
        }
    }

    gate_status keymaker::get_gate_status(gate_id id) const {
        if (const auto *gd = (*this)[id]; gd != nullptr) {
            return gd->status;
        }
        return gate_status::unknown;
    }

    nvs::r<> keymaker::save_gate(gate_data const &gd) {
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
                ours = r->km_pk == keys();
                ESP_LOGI(TAG, "This gate is configured as gate %lu with %s keymaker.",
                         std::uint32_t{r->id}, ours ? "this" : "another");
            } else {
                ESP_LOGI(TAG, "This gate is not configured.");
            }
        }
        return {gid, ours};
    }

    std::optional<p2p::v0::update_settings> keymaker::get_gate_update_settings() {
        ESP_LOGI(TAG, "Bring closer a gate...");
        auto get_info = [&]() -> p2p::r<p2p::v0::update_settings> {
            TRY_RESULT_AS(open_gate_channel(), r_chn) {
                TRY_RESULT_AS(r_chn->remote_gate<p2p::v0::remote_gate>(), r_rg) {
                    TRY(check_if_detected_gate_is_ours(r_rg->get()));
                    TRY_RESULT(r_rg->get().get_update_settings()) {
                        return std::move(*r);
                    }
                }
            }
        };
        if (auto r = get_info(); r) {
            return std::move(*r);
        }
        return std::nullopt;
    }
    std::optional<p2p::v0::wifi_status> keymaker::get_gate_wifi_status() {
        ESP_LOGI(TAG, "Bring closer a gate...");
        auto get_info = [&]() -> p2p::r<p2p::v0::wifi_status> {
            TRY_RESULT_AS(open_gate_channel(), r_chn) {
                TRY_RESULT_AS(r_chn->remote_gate<p2p::v0::remote_gate>(), r_rg) {
                    TRY(check_if_detected_gate_is_ours(r_rg->get()));
                    TRY_RESULT(r_rg->get().get_wifi_status()) {
                        return std::move(*r);
                    }
                }
            }
        };
        if (auto r = get_info(); r) {
            return std::move(*r);
        }
        return std::nullopt;
    }

    bool keymaker::set_gate_update_settings(std::string_view update_channel, bool automatic_updates) {
        ESP_LOGI(TAG, "Bring closer a gate...");
        auto set_updates = [&]() -> p2p::r<> {
            TRY_RESULT_AS(open_gate_channel(), r_chn) {
                TRY_RESULT_AS(r_chn->remote_gate<p2p::v0::remote_gate>(), r_rg) {
                    TRY(check_if_detected_gate_is_ours(r_rg->get()));
                    TRY(r_rg->get().set_update_settings(update_channel, automatic_updates));
                }
            }
            return mlab::result_success;
        };
        return bool(set_updates());
    }

    bool keymaker::connect_gate_wifi(std::string_view ssid, std::string_view password) {
        ESP_LOGI(TAG, "Bring closer a gate...");
        auto connect_wifi = [&]() -> p2p::r<bool> {
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
        };
        const auto r = connect_wifi();
        return r and *r;
    }

    std::optional<gate_info> keymaker::inspect_gate(gate_id id) const {
        std::optional<pub_key> exp_pk = std::nullopt;
        bool ours = true;
        if (id == std::numeric_limits<gate_id>::max()) {
            ESP_LOGI(TAG, "Bring closer a gate...");
            void([&]() -> p2p::r<> {
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
                return mlab::result_success;
            }());
        }
        if (id == std::numeric_limits<gate_id>::max()) {
            return std::nullopt;
        }
        if (not ours) {
            return gate_info{id, gate_status::unknown, {}, *exp_pk};
        }
        if (const auto *gd = (*this)[id]; gd != nullptr) {
            if (exp_pk and *exp_pk != gd->gate_pub_key) {
                ESP_LOGE(TAG, "Mismatching stored public key and remote public key.");
            }
            return gate_info{gd->id, gd->status, gd->notes, gd->gate_pub_key};
        } else {
            ESP_LOGW(TAG, "Gate not found.");
            return std::nullopt;
        }
    }

    namespace cmd {
        template <>
        struct parser<gate_info> {
            [[nodiscard]] static std::string to_string(gate_info const &gi) {
                if (gi.status == gate_status::configured) {
                    return mlab::concatenate({"Gate ", std::to_string(std::uint32_t{gi.id}), "\n",
                                              "Configured, PK ", mlab::data_to_hex_string(gi.public_key.raw_pk()), "\n",
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
        template <>
        struct parser<gate_id> {
            [[nodiscard]] static std::string to_string(gate_id gid) {
                if (gid == std::numeric_limits<gate_id>::max()) {
                    return "gate_id: invalid";
                }
                return mlab::concatenate({"gate-id: ", parser<std::uint32_t>::to_string(std::uint32_t{gid})});
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
        struct parser<p2p::v0::update_settings> {
            [[nodiscard]] static std::string to_string(p2p::v0::update_settings const &us) {
                return mlab::concatenate({us.enable_automatic_update ? "automatic,  from " : "not automatic, from ",
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
    }// namespace cmd

    void keymaker::print_gates() const {
        for (std::size_t i = 0; i < gates().size(); ++i) {
            auto const &g = gates()[i];
            std::printf("%2d. Gate %lu (%s)", i + 1, std::uint32_t{g.id}, to_string(g.status));
            if (g.status == gate_status::configured) {
                auto s = mlab::data_to_hex_string(g.gate_pub_key.raw_pk());
                std::printf(" PK: %s", s.c_str());
            }
            std::printf("\n");
        }
    }

    void keymaker::register_commands(ka::cmd::shell &sh) {
        device::register_commands(sh);
        sh.register_command("gate-configure", *this, &keymaker::configure_gate, {{"gate-id", "gid"}, cmd::flag{"force", false}});
        sh.register_command("gate-delete", *this, &keymaker::delete_gate, {{"gate-id", "gid"}, cmd::flag{"force", false}});
        sh.register_command("gate-register", *this, &keymaker::register_gate, {{"notes", {}, ""}, cmd::flag{"configure", true}});
        sh.register_command("gate-inspect", *this, &keymaker::inspect_gate, {{"gate-id", "gid", std::numeric_limits<gate_id>::max()}});
        sh.register_command("gate-set-notes", *this, &keymaker::set_gate_notes, {{"gate-id", "gid"}, {"notes"}});
        sh.register_command("gate-get-status", *this, &keymaker::get_gate_status, {{"gate-id", "gid"}});
        sh.register_command("gate-wifi-get-status", *this, &keymaker::get_gate_wifi_status, {});
        sh.register_command("gate-wifi-connect", *this, &keymaker::connect_gate_wifi, {{"ssid"}, {"password"}});
        sh.register_command("gate-updates-get-config", *this, &keymaker::get_gate_update_settings, {});
        sh.register_command("gate-updates-set-config", *this, &keymaker::set_gate_update_settings,
                            {{"update-channel", std::optional<std::string>{""}}, cmd::flag{"auto", true}});
        sh.register_command("gate-list", *this, &keymaker::print_gates, {});
    }


    nvs::r<> gate_data::save_to(nvs::namespc &ns) const {
        TRY(ns.set_encode_blob(get_nvs_key(id), *this));
        TRY(ns.commit());
        return mlab::result_success;
    }

    std::string gate_data::get_nvs_key(gate_id gid) {
        std::string buffer;
        buffer.resize(9);
        std::snprintf(buffer.data(), buffer.size(), "%08lx", std::uint32_t{gid});
        buffer.resize(8);
        return buffer;
    }

    nvs::r<gate_data> gate_data::load_from(nvs::const_namespc const &ns, gate_id gid) {
        const auto key = get_nvs_key(gid);
        return ns.get_parse_blob<gate_data>(key.c_str());
    }

    std::vector<gate_data> gate_data::load_from(nvs::const_namespc const &ns) {
        std::vector<gate_data> retval;
        for (gate_id gid = std::numeric_limits<gate_id>::min(); gid < std::numeric_limits<gate_id>::max(); gid = gate_id{gid + 1}) {
            if (const auto r = load_from(ns, gid); r) {
                retval.push_back(*r);
            } else if (r.error() == nvs::error::not_found) {
                break;
            } else {
                ESP_LOGE(TAG, "Unable to load gate %lu, error %s", std::uint32_t{gid}, to_string(r.error()));
                retval.push_back(gate_data{gid, {}, gate_status::unknown, {}, {}});
            }
        }
        return retval;
    }
}// namespace ka

namespace mlab {
    bin_data &operator<<(bin_data &bd, ka::gate_data const &gd) {
        const auto sz = 4 + 1 + ka::raw_pub_key::array_size + ka::gate_base_key::array_size + 4 + gd.notes.size();
        return bd << prealloc(sz) << gd.id << gd.status << gd.gate_pub_key << gd.app_base_key << length_encoded << gd.notes;
    }

    bin_stream &operator>>(bin_stream &s, ka::gate_data &gd) {
        if (s.remaining() < 4 + 1 + ka::raw_pub_key::array_size + ka::gate_base_key::array_size + 4) {
            s.set_bad();
            return s;
        }
        ka::gate_data new_gd{};
        s >> new_gd.id >> new_gd.status >> new_gd.gate_pub_key >> new_gd.app_base_key >> length_encoded >> new_gd.notes;
        if (s.bad()) {
            return s;
        }
        gd = new_gd;
        return s;
    }

}// namespace mlab