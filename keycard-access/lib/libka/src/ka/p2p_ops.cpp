//
// Created by spak on 1/20/23.
//

#include <desfire/esp32/utils.hpp>
#include <ka/gate.hpp>
#include <ka/gpio_auth_responder.hpp>
#include <ka/p2p_ops.hpp>
#include <ka/secure_p2p.hpp>
#include <mlab/result_macro.hpp>
#include <mlab/strutils.hpp>
#include <pn532/controller.hpp>
#include <thread>

#define TAG "P2P"

#undef MLAB_RESULT_LOG_PREFIX
#define MLAB_RESULT_LOG_PREFIX TAG

namespace ka::rpc {
    template <>
    struct use_default_serialization<ka::pub_key> : std::true_type {};
    template <>
    struct use_default_serialization<ka::gate_id> : std::true_type {};
    template <>
    struct use_default_serialization<ka::fw_info> : std::true_type {};
    template <>
    struct use_default_serialization<ka::p2p::gate_update_config> : std::true_type {};
    template <>
    struct use_default_serialization<ka::p2p::gate_wifi_status> : std::true_type {};
    template <>
    struct use_default_serialization<ka::p2p::gate_registration_info> : std::true_type {};
    template <>
    struct use_default_serialization<ka::update_status> : std::true_type {};
    template <>
    struct use_default_serialization<ka::gpio_responder_config> : std::true_type {};
    template <>
    struct use_default_serialization<ka::release_info> : std::true_type {};
    template <>
    struct use_default_serialization<ka::gate_base_key> : std::true_type {};

    template <class T>
    struct serializer<ka::p2p::r<T>> {
        static void serialize(mlab::bin_data &bd, ka::p2p::r<T> const &r) {
            bd << bool(r);
            if (r) {
                serializer<T>::serialize(bd, *r);
            } else {
                bd << r.error();
            }
        }

        [[nodiscard]] static ka::p2p::r<T> deserialize(mlab::bin_stream &s) {
            bool is_ok = false;
            s >> is_ok;
            if (not s.bad()) {
                if (is_ok) {
                    return serializer<T>::deserialize(s);
                } else {
                    ka::p2p::error e{};
                    s >> e;
                    return e;
                }
            }
            return ka::p2p::error{};
        }
    };

    template <>
    struct serializer<ka::p2p::r<>> {
        static void serialize(mlab::bin_data &bd, ka::p2p::r<> const &r) {
            bd << bool(r);
            if (not r) {
                bd << r.error();
            }
        }

        [[nodiscard]] static ka::p2p::r<> deserialize(mlab::bin_stream &s) {
            bool is_ok = false;
            s >> is_ok;
            if (not s.bad()) {
                if (is_ok) {
                    return mlab::result_success;
                } else {
                    ka::p2p::error e{};
                    s >> e;
                    return e;
                }
            }
            return ka::p2p::error{};
        }
    };
}// namespace ka::rpc

namespace ka::p2p {

    const char *to_string(error e) {
        switch (e) {
            case error::unauthorized:
                return "unauthorized";
            case error::invalid_argument:
                return "invalid argument";
            case error::invalid_operation:
                return "invalid operation";
        }
        return "UNKNOWN";
    }

    local_gate::local_gate(gate &g, std::shared_ptr<secure_initiator> initiator)
        : _g{g},
          _sec_layer{std::move(initiator)},
          _b{std::make_unique<initiator_bridge_interface>(_sec_layer)} {
        _b.register_command(&local_gate::get_fw_info, *this, "get_fw_info");
        _b.register_command(&local_gate::get_update_settings, *this, "get_update_settings");
        _b.register_command(&local_gate::get_wifi_status, *this, "get_wifi_status");
        _b.register_command(&local_gate::is_updating, *this, "is_updating");
        _b.register_command(&local_gate::get_gpio_config, *this, "get_gpio_config");
        _b.register_command(&local_gate::get_backend_url, *this, "get_backend_url");
        _b.register_command(&local_gate::get_registration_info, *this, "get_registration_info");
        _b.register_command(&local_gate::register_gate, *this, "register_gate");
        _b.register_command(&local_gate::set_update_settings, *this, "set_update_settings");
        _b.register_command(&local_gate::update_manually, *this, "update_manually");
        _b.register_command(&local_gate::set_backend_url, *this, "set_backend_url");
        _b.register_command(&local_gate::set_gpio_config, *this, "set_gpio_config");
        _b.register_command(&local_gate::reset_gate, *this, "reset_gate");
        _b.register_command(&local_gate::connect_wifi, *this, "connect_wifi");
        _b.register_command(&local_gate::disconnect, *this, "disconnect");
        _b.register_command(&local_gate::restart, *this, "restart");
        _b.register_command(&local_gate::check_for_updates, *this, "check_for_updates");
        _b.register_command(&local_gate::update_now, *this, "update_now");
    }

    void local_gate::serve_loop() {
        if (_sec_layer->handshake()) {
            _b.serve_loop();
        }
    }

    pub_key local_gate::peer_pub_key() const {
        if (_sec_layer == nullptr) {
            ESP_LOGE(TAG, "Not connected.");
            return pub_key{};
        }
        return _sec_layer->peer_pub_key();
    }

    fw_info local_gate::get_fw_info() const {
        return fw_info::get_running_fw();
    }

    gate_update_config local_gate::get_update_settings() const {
        return gate_update_config{std::string{_g.update_channel()}, _g.updates_automatically()};
    }

    gate_wifi_status local_gate::get_wifi_status() const {
        if (const auto ssid = _g.wifi_get_ssid(); ssid) {
            return gate_wifi_status{*ssid, _g.wifi_test()};
        }
        return gate_wifi_status{"", false};
    }

    update_status local_gate::is_updating() const {
        return _g.is_updating();
    }

    gpio_responder_config local_gate::get_gpio_config() const {
        return gpio_responder_config::get_global_config();
    }

    std::string local_gate::get_backend_url() const {
        ESP_LOGE(TAG, "get_backend_url not yet implemented");
        return "";
    }

    gate_registration_info local_gate::get_registration_info() const {
        return gate_registration_info{_g.public_info(), _g.keymaker_pk()};
    }

    r<release_info> local_gate::check_for_updates() {
        TRY(assert_peer_is_keymaker(true));
        if (auto ri = _g.check_for_updates(); ri) {
            return std::move(*ri);
        }
        return release_info{};
    }

    r<gate_base_key> local_gate::register_gate(gate_id requested_id) {
        if (_g.is_configured()) {
            return error::invalid_operation;
        }
        if (const auto bk = _g.configure(requested_id, peer_pub_key()); not bk) {
            return error::invalid_operation;
        } else {
            return *bk;
        }
    }

    r<> local_gate::set_update_settings(std::string_view update_channel, bool automatic_updates) {
        TRY(assert_peer_is_keymaker(true));
        _g.set_update_automatically(automatic_updates);
        if (not update_channel.empty() and not _g.set_update_channel(update_channel, true)) {
            return error::invalid_argument;
        }
        return mlab::result_success;
    }

    r<> local_gate::update_manually(std::string_view fw_url) {
        TRY(assert_peer_is_keymaker(true));
        auto body = [from = std::string{fw_url}, &g = _g]() {
            g.update_manually(from);
        };
        std::thread upd_th{body};
        upd_th.detach();
        return mlab::result_success;
    }

    r<> local_gate::set_backend_url(std::string_view, std::string_view) {
        TRY(assert_peer_is_keymaker());
        ESP_LOGE(TAG, "set_backend_url not yet implemented");
        return error::invalid_operation;
    }

    r<> local_gate::set_gpio_config(gpio_responder_config cfg) {
        TRY(assert_peer_is_keymaker());
        if (not gpio_responder_config::set_global_config(cfg)) {
            return error::invalid_argument;
        }
        return mlab::result_success;
    }

    r<> local_gate::reset_gate() {
        TRY(assert_peer_is_keymaker());
        _g.reset();
        return mlab::result_success;
    }

    r<> local_gate::restart() {
        TRY(assert_peer_is_keymaker(true));
        std::thread restart_th{[]() {
          std::this_thread::sleep_for(2s);
          esp_restart();
        }};
        restart_th.detach();
        _b.serve_stop();
        return mlab::result_success;
    }

    r<release_info> local_gate::update_now() {
        TRY(assert_peer_is_keymaker(true));
        if (const auto ri = _g.check_for_updates(); ri) {
            auto body = [from = ri->firmware_url, &g = _g]() {
                g.update_manually(from);
            };
            std::thread upd_th{body};
            upd_th.detach();
            return *ri;
        } else {
            return release_info{};
        }
    }

    r<bool> local_gate::connect_wifi(std::string_view ssid, std::string_view password) {
        TRY(assert_peer_is_keymaker(true));
        return _g.wifi_connect(ssid, password);
    }

    r<> local_gate::assert_peer_is_keymaker(bool allow_unconfigured) const {
        if (_g.is_configured()) {
            if (peer_pub_key() != _g.keymaker_pk()) {
                return error::unauthorized;
            }
        } else if (not allow_unconfigured) {
            return error::invalid_operation;
        }
        return mlab::result_success;
    }

    void local_gate::disconnect() {
        _b.serve_stop();
    }


    remote_gate::remote_gate(std::shared_ptr<secure_target> target)
        : _sec_layer{std::move(target)},
          _b{std::make_unique<target_bridge_interface>(_sec_layer)} {
        void([&]() -> pn532::result<> {
            TRY(_sec_layer->handshake());
            return mlab::result_success;
        }());
    }

    rpc::r<fw_info> remote_gate::get_fw_info() const {
        return _b.remote_invoke(&local_gate::get_fw_info, "get_fw_info");
    }

    rpc::r<gate_update_config> remote_gate::get_update_settings() const {
        return _b.remote_invoke(&local_gate::get_update_settings, "get_update_settings");
    }

    rpc::r<gate_wifi_status> remote_gate::get_wifi_status() const {
        return _b.remote_invoke(&local_gate::get_wifi_status, "get_wifi_status");
    }

    rpc::r<update_status> remote_gate::is_updating() const {
        return _b.remote_invoke(&local_gate::is_updating, "is_updating");
    }

    rpc::r<gpio_responder_config> remote_gate::get_gpio_config() const {
        return _b.remote_invoke(&local_gate::get_gpio_config, "get_gpio_config");
    }

    rpc::r<std::string> remote_gate::get_backend_url() const {
        return _b.remote_invoke(&local_gate::get_backend_url, "get_backend_url");
    }

    rpc::r<gate_registration_info> remote_gate::get_registration_info() const {
        return _b.remote_invoke(&local_gate::get_registration_info, "get_registration_info");
    }

    rpc::r<r<release_info>> remote_gate::check_for_updates() {
        return _b.remote_invoke(&local_gate::check_for_updates, "check_for_updates");
    }

    rpc::r<r<gate_base_key>> remote_gate::register_gate(gate_id requested_id) {
        return _b.remote_invoke(&local_gate::register_gate, "register_gate", requested_id);
    }

    rpc::r<r<>> remote_gate::set_update_settings(std::string_view update_channel, bool automatic_updates) {
        return _b.remote_invoke(&local_gate::set_update_settings, "set_update_settings", update_channel, automatic_updates);
    }

    rpc::r<r<>> remote_gate::update_manually(std::string_view fw_url) {
        return _b.remote_invoke(&local_gate::update_manually, "update_manually", fw_url);
    }

    rpc::r<r<>> remote_gate::set_backend_url(std::string_view url, std::string_view api_key) {
        return _b.remote_invoke(&local_gate::set_backend_url, "set_backend_url", url, api_key);
    }

    rpc::r<r<>> remote_gate::set_gpio_config(gpio_responder_config cfg) {
        return _b.remote_invoke(&local_gate::set_gpio_config, "set_gpio_config", cfg);
    }

    rpc::r<r<>> remote_gate::reset_gate() {
        return _b.remote_invoke(&local_gate::reset_gate, "reset_gate");
    }

    rpc::r<r<release_info>> remote_gate::update_now() {
        return _b.remote_invoke(&local_gate::update_now, "update_now");
    }

    rpc::r<r<bool>> remote_gate::connect_wifi(std::string_view ssid, std::string_view password) {
        return _b.remote_invoke(&local_gate::connect_wifi, "connect_wifi", ssid, password);
    }

    rpc::r<> remote_gate::bye() {
        return _b.remote_invoke(&local_gate::disconnect, "disconnect");
    }

    rpc::r<r<>> remote_gate::restart_gate() {
        return _b.remote_invoke(&local_gate::restart, "restart");
    }
}// namespace ka::p2p

namespace mlab {
    bin_stream &operator>>(bin_stream &s, ka::fw_info &fwinfo) {
        s >> fwinfo.semantic_version;
        s >> length_encoded >> fwinfo.commit_info;
        s >> length_encoded >> fwinfo.app_name;
        s >> length_encoded >> fwinfo.platform_code;
        return s;
    }

    bin_data &operator<<(bin_data &bd, ka::fw_info const &fwinfo) {
        return bd << fwinfo.semantic_version
                  << length_encoded << fwinfo.commit_info
                  << length_encoded << fwinfo.app_name
                  << length_encoded << fwinfo.platform_code;
    }

    bin_stream &operator>>(bin_stream &s, ka::p2p::gate_registration_info &rinfo) {
        s >> rinfo.id >> rinfo.pk >> rinfo.keymaker_pk;
        return s;
    }

    bin_data &operator<<(bin_data &bd, ka::p2p::gate_registration_info const &rinfo) {
        return bd << prealloc(ka::raw_pub_key::array_size * 2 + 4) << rinfo.id << rinfo.pk << rinfo.keymaker_pk;
    }

    bin_stream &operator>>(bin_stream &s, ka::gate_id &gid) {
        std::uint32_t v{};
        s >> lsb32 >> v;
        if (not s.bad()) {
            gid = ka::gate_id{v};
        }
        return s;
    }

    bin_data &operator<<(bin_data &bd, ka::gate_id const &gid) {
        return bd << lsb32 << std::uint32_t(gid);
    }

    bin_stream &operator>>(bin_stream &s, ka::p2p::gate_update_config &usettings) {
        s >> length_encoded >> usettings.update_channel >> usettings.enable_automatic_update;
        return s;
    };

    bin_data &operator<<(bin_data &bd, ka::p2p::gate_update_config const &usettings) {
        return bd << length_encoded << usettings.update_channel << usettings.enable_automatic_update;
    }

    bin_stream &operator>>(bin_stream &s, ka::p2p::gate_wifi_status &wfsettings) {
        s >> length_encoded >> wfsettings.ssid >> wfsettings.operational;
        return s;
    }

    bin_stream &operator>>(bin_stream &s, ka::release_info &ri) {
        s >> ri.semantic_version >> length_encoded >> ri.firmware_url;
        return s;
    }

    bin_stream &operator>>(bin_stream &s, ka::update_status &us) {
        std::string from{};
        s >> length_encoded >> from;
        if (not s.bad()) {
            if (from.empty()) {
                us = ka::update_status{std::nullopt};
            } else {
                us = ka::update_status{std::move(from)};
            }
        }
        return s;
    }

    bin_data &operator<<(bin_data &bd, ka::update_status const &us) {
        if (us.updating_from == std::nullopt) {
            return bd << mlab::length_encoded << "";
        } else {
            return bd << mlab::length_encoded << *us.updating_from;
        }
    }

    bin_data &operator<<(bin_data &bd, ka::release_info const &ri) {
        return bd << ri.semantic_version << length_encoded << ri.firmware_url;
    }

    bin_data &operator<<(bin_data &bd, ka::p2p::gate_wifi_status const &wfsettings) {
        return bd << length_encoded << wfsettings.ssid << wfsettings.operational;
    }

    bin_stream &operator>>(bin_stream &s, semver::version &v) {
        if (s.bad()) {
            return s;
        }
        if (s.remaining() < 5) {
            s.set_bad();
            return s;
        }

        s >> v.major >> v.minor >> v.patch >> v.prerelease_type >> v.prerelease_number;
        return s;
    }

    bin_data &operator<<(bin_data &bd, semver::version const &v) {
        return bd << v.major << v.minor << v.patch << v.prerelease_type << v.prerelease_number;
    }
}// namespace mlab