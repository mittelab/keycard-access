//
// Created by spak on 1/20/23.
//

#include <desfire/esp32/utils.hpp>
#include <ka/gate.hpp>
#include <ka/keymaker.hpp>
#include <ka/p2p_ops.hpp>
#include <ka/secure_p2p.hpp>
#include <mlab/result_macro.hpp>
#include <mlab/strutils.hpp>
#include <pn532/controller.hpp>
#include <thread>

#define TAG "P2P"

#undef MLAB_RESULT_LOG_PREFIX
#define MLAB_RESULT_LOG_PREFIX TAG

namespace ka::p2p {
    namespace bits {
        static constexpr std::uint8_t command_hello = 0x00;
        static constexpr std::uint8_t command_bye = 0x01;
    }// namespace bits


    error proto_status_to_error(proto_status s) {
        switch (s) {
            case proto_status::ok:
                ESP_LOGE(TAG, "Proto status OK is not an error.");
                return error::p2p_app_error;
            case proto_status::unauthorized:
                return error::unauthorized;
            case proto_status::invalid:
                return error::invalid;
            case proto_status::arg_error:
                return error::arg_error;
            default:
                [[fallthrough]];
            case proto_status::ready_for_cmd:
                [[fallthrough]];
            case proto_status::did_read_resp:
                ESP_LOGE(TAG, "Broken NFC P2P flow, received status byte %02x", static_cast<std::uint8_t>(s));
                [[fallthrough]];
            case proto_status::malformed:
                return error::malformed;
        }
    }

    proto_status error_to_proto_status(error e) {
        switch (e) {
            case error::malformed:
                return proto_status::malformed;
            case error::unauthorized:
                return proto_status::unauthorized;
            case error::invalid:
                return proto_status::invalid;
            case error::arg_error:
                return proto_status::arg_error;
            default:
                ESP_LOGE(TAG, "Broken NFC P2P flow, received status byte %02x", static_cast<std::uint8_t>(e));
                return proto_status::malformed;
        }
    }

    const char *to_string(error e) {
        switch (e) {
            case error::malformed:
                return "malformed command";
            case error::unauthorized:
                return "unauthorized";
            case error::invalid:
                return "invalid";
            case error::p2p_timeout:
                return to_string(pn532::channel_error::timeout);
            case error::p2p_hw_error:
                return to_string(pn532::channel_error::hw_error);
            case error::p2p_malformed:
                return to_string(pn532::channel_error::malformed);
            case error::p2p_app_error:
                return to_string(pn532::channel_error::app_error);
            default:
                return "UNKNOWN";
        }
    }

    remote_gate_base::remote_gate_base(secure_target &local_interface) : _local_interface{local_interface} {
        if (not local_interface.did_handshake()) {
            ESP_LOGE(TAG, "You must have performed the handshake before!");
        }
    }

    r<gate_fw_info> remote_gate_base::hello_and_assert_protocol(std::uint8_t proto_version) {
        auto r = remote_gate_base::hello();
        if (r and r->proto_version != proto_version) {
            ESP_LOGE(TAG, "Mismatching protocol version %d", r->proto_version);
            return error::invalid;
        }
        return r;
    }
    r<> remote_gate_base::command(std::uint8_t command_code, mlab::bin_data cmd) {
        if (auto r = local_interface().receive(5s); r) {
            if (r->size() != 1 or r->front() != static_cast<std::uint8_t>(proto_status::ready_for_cmd)) {
                ESP_LOGE(TAG, "Invalid protocol flow, I got %d bytes:", r->size());
                ESP_LOG_BUFFER_HEX_LEVEL(TAG, r->data(), r->size(), ESP_LOG_ERROR);
                return error::malformed;
            }
        }
        // Command code comes last so we can pop it
        cmd.push_back(command_code);
        /**
         * @note Due to the fact that a gate operates as an initiator, we actually need to wait for the green light
         * to send another command.
         */
        if (auto r = local_interface().send(cmd, 5s); not r) {
            return channel_error_to_p2p_error(r.error());
        }
        return mlab::result_success;
    }

    r<mlab::bin_data> remote_gate_base::command_response(std::uint8_t command_code, mlab::bin_data cmd) {
        TRY(command(command_code, std::move(cmd)));
        if (auto r_recv = local_interface().receive(5s); r_recv) {
            // Mark that the response has been received
            if (auto r_confirm = local_interface().send(mlab::bin_data::chain(proto_status::did_read_resp), 5s); not r_confirm) {
                ESP_LOGW(TAG, "Unable to confirm the response was received, status %s", to_string(r_confirm.error()));
            }
            // Last byte identifies the status code
            if (r_recv->empty()) {
                return error::malformed;
            }
            const auto s = static_cast<proto_status>(r_recv->back());
            r_recv->pop_back();
            if (s == proto_status::ok) {
                return std::move(*r_recv);
            } else {
                return proto_status_to_error(s);
            }
        } else {
            return channel_error_to_p2p_error(r_recv.error());
        }
    }

    bool assert_stream_healthy(mlab::bin_stream const &s) {
        if (not s.eof()) {
            ESP_LOGW(TAG, "Stray %u bytes at the end of the stream.", s.remaining());
            return false;
        } else if (s.bad()) {
            ESP_LOGW(TAG, "Malformed or unreadable response.");
            return false;
        }
        return true;
    }


    r<gate_fw_info> remote_gate_base::hello() {
        return command_parse_response<gate_fw_info>(bits::command_hello);
    }

    void remote_gate_base::bye() {
        void(command(bits::command_bye, {}));
    }

    local_gate_base::local_gate_base(secure_initiator &local_interface, ka::gate &g) : _local_interface{local_interface}, _g{g} {
        if (not local_interface.did_handshake()) {
            ESP_LOGE(TAG, "You must have performed the handshake before!");
        }
    }

    r<std::uint8_t, mlab::bin_data> local_gate_base::command_receive() {
        if (auto r = local_interface().communicate(mlab::bin_data::chain(proto_status::ready_for_cmd), 5s); r) {
            if (r->empty()) {
                return error::malformed;
            }
            const auto b = r->back();
            r->pop_back();
            return {b, std::move(*r)};
        } else {
            return channel_error_to_p2p_error(r.error());
        }
    }

    r<> local_gate_base::response_send(r<std::string> const &response) {
        if (not response) {
            return response_send(error_to_proto_status(response.error()), {});
        } else {
            return response_send(proto_status::ok, mlab::bin_data::chain(mlab::length_encoded, *response));
        }
    }

    r<> local_gate_base::response_send(proto_status s, mlab::bin_data resp) {
        resp << s;
        if (auto r = local_interface().communicate(resp, 5s); r) {
            if (r->size() != 1 or r->front() != static_cast<std::uint8_t>(proto_status::did_read_resp)) {
                ESP_LOGE(TAG, "Invalid protocol flow, I got %d bytes:", r->size());
                ESP_LOG_BUFFER_HEX_LEVEL(TAG, r->data(), r->size(), ESP_LOG_ERROR);
                return error::malformed;
            }
            return mlab::result_success;
        } else {
            return channel_error_to_p2p_error(r.error());
        }
    }

    r<gate_fw_info> local_gate_base::hello(const mlab::bin_data &body) {
        if (not assert_stream_healthy(mlab::bin_stream{body})) {
            return error::malformed;
        }
        return hello();
    }

    r<gate_fw_info> local_gate_base::hello() {
        return gate_fw_info{fw_info::get_running_fw(), protocol_version()};
    }

    void local_gate_base::serve_loop() {
        for (auto r_recv = command_receive(); r_recv; r_recv = command_receive()) {
            if (auto r_repl = try_serve_command(r_recv->first, r_recv->second); r_repl) {
                switch (*r_repl) {
                    case serve_outcome::ok:
                        continue;
                    case serve_outcome::halt:
                        return;
                    case serve_outcome::unknown:
                        ESP_LOGE(TAG, "Unsupported command code %02x", r_recv->first);
                        if (auto r_malf = response_send(proto_status::malformed, {}); not r_malf) {
                            ESP_LOGW(TAG, "Unable to send reply, %s", to_string(r_malf.error()));
                        }
                        break;
                }
            } else {
                ESP_LOGW(TAG, "Unable to send reply, %s", to_string(r_repl.error()));
            }
        }
    }

    r<> local_gate_base::assert_peer_is_keymaker() const {
        if (not g().is_configured()) {
            return error::invalid;
        }
        if (local_interface().peer_pub_key() != g().keymaker_pk()) {
            return error::unauthorized;
        }
        return mlab::result_success;
    }

    r<local_gate_base::serve_outcome> local_gate_base::try_serve_command(std::uint8_t command_code, mlab::bin_data const &body) {
        switch (command_code) {
            case bits::command_hello:
                TRY(response_send(hello(body)));
                return serve_outcome::ok;
            case bits::command_bye:
                // Special case:
                return serve_outcome::halt;
            default:
                return serve_outcome::unknown;
        }
    }

    namespace v0 {
        enum struct commands : std::uint8_t {
            _reserved1 [[maybe_unused]] = bits::command_hello,///< Reserved, make sure it does not clash
            _reserved2 [[maybe_unused]] = bits::command_bye,  ///< Reserved, make sure it does not clash
            get_update_settings = 0x02,
            set_update_settings = 0x03,
            get_wifi_status = 0x04,
            connect_wifi = 0x05,
            get_registration_info = 0x06,
            register_gate = 0x07,
            reset_gate = 0x08,
            check_for_updates = 0x09,
            is_updating = 0x0a,
            update_now = 0x0b,
            update_manually = 0x0c,
            get_backend_url = 0x0d,
            set_backend_url = 0x0e,
        };

        r<gate_registration_info> remote_gate::get_registration_info() {
            auto r = command_parse_response<gate_registration_info>(commands::get_registration_info);
            if (r) {
                if (r->pk != local_interface().peer_pub_key()) {
                    ESP_LOGE(TAG, "Mismatching declared public key with peer public key!");
                    return error::invalid;
                }
            }
            return r;
        }

        r<update_config> remote_gate::get_update_settings() {
            return command_parse_response<update_config>(commands::get_update_settings);
        }

        r<> remote_gate::set_update_settings(std::string_view update_channel, bool automatic_updates) {
            return command_parse_response<void>(
                    commands::set_update_settings,
                    mlab::prealloc{update_channel.size() + 6},
                    mlab::length_encoded, update_channel,
                    automatic_updates);
        }

        r<release_info> remote_gate::check_for_updates() {
            return command_parse_response<release_info>(commands::check_for_updates);
        }

        r<std::string> remote_gate::is_updating() {
            if (const auto r = command_response(static_cast<std::uint8_t>(commands::is_updating), {}); r) {
                mlab::bin_stream s{*r};
                std::string retval{};
                s >> mlab::length_encoded >> retval;
                if (assert_stream_healthy(s)) {
                    return retval;
                } else {
                    return error::malformed;
                }
            } else {
                return r.error();
            }
        }

        r<release_info> remote_gate::update_now() {
            return command_parse_response<release_info>(commands::update_now);
        }

        r<> remote_gate::update_manually(std::string_view fw_url) {
            return command_parse_response<void>(
                    commands::update_manually,
                    mlab::length_encoded, fw_url);
        }

        r<> remote_gate::set_backend_url(std::string_view url, std::string_view api_key) {
            return command_parse_response<void>(
                    commands::set_backend_url,
                    mlab::length_encoded, url, mlab::length_encoded, api_key);
        }

        r<std::string> remote_gate::get_backend_url() {
            if (const auto r = command_response(static_cast<std::uint8_t>(commands::get_backend_url), {}); r) {
                mlab::bin_stream s{*r};
                std::string retval{};
                s >> mlab::length_encoded >> retval;
                if (assert_stream_healthy(s)) {
                    return retval;
                } else {
                    return error::malformed;
                }
            } else {
                return r.error();
            }
        }

        r<wifi_status> remote_gate::get_wifi_status() {
            return command_parse_response<wifi_status>(commands::get_wifi_status);
        }

        r<bool> remote_gate::connect_wifi(std::string_view ssid, std::string_view password) {
            return command_parse_response<bool>(commands::connect_wifi,
                                                mlab::prealloc{ssid.size() + password.size() + 9},
                                                mlab::length_encoded, ssid,
                                                mlab::length_encoded, password);
        }

        r<gate_fw_info> remote_gate::hello() {
            return hello_and_assert_protocol(0);
        }

        r<gate_base_key> remote_gate::register_gate(gate_id requested_id) {
            return command_parse_response<gate_base_key>(commands::register_gate, requested_id);
        }

        r<> remote_gate::reset_gate() {
            return command_parse_response<void>(commands::reset_gate);
        }

        r<update_config> local_gate::get_update_settings(mlab::bin_data const &body) {
            if (not assert_stream_healthy(mlab::bin_stream{body})) {
                return error::malformed;
            }
            return get_update_settings();
        }

        r<> local_gate::set_update_settings(mlab::bin_data const &body) {
            std::string update_channel{};
            bool automatic_updates = false;
            mlab::bin_stream s{body};
            s >> mlab::length_encoded >> update_channel >> automatic_updates;
            if (not assert_stream_healthy(s)) {
                return error::malformed;
            }
            return set_update_settings(update_channel, automatic_updates);
        }

        r<release_info> local_gate::check_for_updates(mlab::bin_data const &body) {
            if (not assert_stream_healthy(mlab::bin_stream{body})) {
                return error::malformed;
            }
            return check_for_updates();
        }

        r<std::string> local_gate::is_updating(mlab::bin_data const &body) {
            if (not assert_stream_healthy(mlab::bin_stream{body})) {
                return error::malformed;
            }
            return is_updating();
        }

        r<release_info> local_gate::update_now(mlab::bin_data const &body) {
            if (not assert_stream_healthy(mlab::bin_stream{body})) {
                return error::malformed;
            }
            return update_now();
        }

        r<> local_gate::update_manually(mlab::bin_data const &body) {
            std::string url = {};
            mlab::bin_stream s{body};
            s >> mlab::length_encoded >> url;
            if (not assert_stream_healthy(s)) {
                return error::malformed;
            }
            return update_manually(url);
        }

        r<> local_gate::set_backend_url(mlab::bin_data const &body) {
            std::string url = {}, api_key = {};
            mlab::bin_stream s{body};
            s >> mlab::length_encoded >> url >> mlab::length_encoded >> api_key;
            if (not assert_stream_healthy(s)) {
                return error::malformed;
            }
            return set_backend_url(url, api_key);
        }

        r<std::string> local_gate::get_backend_url(mlab::bin_data const &body) {
            if (not assert_stream_healthy(mlab::bin_stream{body})) {
                return error::malformed;
            }
            return get_backend_url();
        }

        r<wifi_status> local_gate::get_wifi_status(mlab::bin_data const &body) {
            if (not assert_stream_healthy(mlab::bin_stream{body})) {
                return error::malformed;
            }
            return get_wifi_status();
        }

        r<bool> local_gate::connect_wifi(mlab::bin_data const &body) {
            std::string ssid = {}, password = {};
            mlab::bin_stream s{body};
            s >> mlab::length_encoded >> ssid >> mlab::length_encoded >> password;
            if (not assert_stream_healthy(s)) {
                return error::malformed;
            }
            return connect_wifi(ssid, password);
        }

        r<gate_registration_info> local_gate::get_registration_info(mlab::bin_data const &body) {
            if (not assert_stream_healthy(mlab::bin_stream{body})) {
                return error::malformed;
            }
            return get_registration_info();
        }

        r<gate_base_key> local_gate::register_gate(mlab::bin_data const &body) {
            gate_id gid = std::numeric_limits<gate_id>::max();
            mlab::bin_stream s{body};
            s >> gid;
            if (not assert_stream_healthy(s)) {
                return error::malformed;
            }
            return register_gate(gid);
        }

        r<> local_gate::reset_gate(mlab::bin_data const &body) {
            if (not assert_stream_healthy(mlab::bin_stream{body})) {
                return error::malformed;
            }
            return reset_gate();
        }

        r<local_gate_base::serve_outcome> local_gate::try_serve_command(std::uint8_t command_code, mlab::bin_data const &body) {
            TRY_RESULT(local_gate_base::try_serve_command(command_code, body)) {
                if (*r != serve_outcome::unknown) {
                    return *r;
                }
            }
            // Handle our own commands
            const auto typed_cmd_code = static_cast<commands>(command_code);
            switch (typed_cmd_code) {
                case commands::get_update_settings:
                    TRY(response_send(get_update_settings(body)));
                    return serve_outcome::ok;
                case commands::set_update_settings:
                    TRY(response_send(set_update_settings(body)));
                    return serve_outcome::ok;
                case commands::get_wifi_status:
                    TRY(response_send(get_wifi_status(body)));
                    return serve_outcome::ok;
                case commands::connect_wifi:
                    TRY(response_send(connect_wifi(body)));
                    return serve_outcome::ok;
                case commands::get_registration_info:
                    TRY(response_send(get_registration_info(body)));
                    return serve_outcome::ok;
                case commands::register_gate:
                    TRY(response_send(register_gate(body)));
                    return serve_outcome::ok;
                case commands::reset_gate:
                    TRY(response_send(reset_gate(body)));
                    return serve_outcome::ok;
                case commands::check_for_updates:
                    TRY(response_send(check_for_updates(body)));
                    return serve_outcome::ok;
                case commands::is_updating:
                    TRY(response_send(is_updating(body)));
                    return serve_outcome::ok;
                case commands::update_now:
                    TRY(response_send(update_now(body)));
                    return serve_outcome::ok;
                case commands::update_manually:
                    TRY(response_send(update_manually(body)));
                    return serve_outcome::ok;
                case commands::get_backend_url:
                    TRY(response_send(get_backend_url(body)));
                    return serve_outcome::ok;
                case commands::set_backend_url:
                    TRY(response_send(set_backend_url(body)));
                    return serve_outcome::ok;
                case commands::_reserved1:
                    [[fallthrough]];
                case commands::_reserved2:
                    break;
            }
            return serve_outcome::unknown;
        }

        r<update_config> local_gate::get_update_settings() {
            return update_config{std::string{g().update_channel()}, g().updates_automatically()};
        }

        r<wifi_status> local_gate::get_wifi_status() {
            if (const auto ssid = g().wifi_get_ssid(); ssid) {
                return wifi_status{*ssid, g().wifi_test()};
            }
            return wifi_status{"", false};
        }

        r<release_info> local_gate::check_for_updates() {
            TRY(assert_peer_is_keymaker());
            if (auto ri = g().check_for_updates(); ri) {
                return std::move(*ri);
            }
            return release_info{};
        }

        r<std::string> local_gate::is_updating() {
            if (auto upd_from = g().is_updating(); upd_from) {
                return std::move(*upd_from);
            }
            return std::string{};
        }

        r<release_info> local_gate::update_now() {
            TRY(assert_peer_is_keymaker());
            if (const auto ri = g().check_for_updates(); ri) {
                auto body = [from = ri->firmware_url, &g = g()]() {
                    g.update_manually(from);
                };
                std::thread upd_th{body};
                return std::move(*ri);
            } else {
                return release_info{};
            }
        }

        r<> local_gate::update_manually(std::string_view fw_url) {
            TRY(assert_peer_is_keymaker());
            auto body = [from = std::string{fw_url}, &g = g()]() {
                g.update_manually(from);
            };
            std::thread upd_th{body};
            return mlab::result_success;
        }

        r<> local_gate::set_backend_url(std::string_view, std::string_view) {
            ESP_LOGE(TAG, "set_backend_url not yet implemented");
            return error::invalid;
        }

        r<std::string> local_gate::get_backend_url() {
            ESP_LOGE(TAG, "get_backend_url not yet implemented");
            return error::invalid;
        }

        r<gate_registration_info> local_gate::get_registration_info() {
            return gate_registration_info{g().public_info(), g().keymaker_pk()};
        }

        r<> local_gate::set_update_settings(std::string_view update_channel, bool automatic_updates) {
            TRY(assert_peer_is_keymaker());
            g().set_update_automatically(automatic_updates);
            if (not update_channel.empty() and not g().set_update_channel(update_channel, true)) {
                return error::arg_error;
            }
            return mlab::result_success;
        }

        r<bool> local_gate::connect_wifi(std::string_view ssid, std::string_view password) {
            TRY(assert_peer_is_keymaker());
            return g().wifi_connect(ssid, password);
        }

        r<gate_base_key> local_gate::register_gate(gate_id requested_id) {
            if (g().is_configured()) {
                return error::invalid;
            }
            if (const auto bk = g().configure(requested_id, local_interface().peer_pub_key()); not bk) {
                return error::invalid;
            } else {
                return *bk;
            }
        }

        r<> local_gate::reset_gate() {
            TRY(assert_peer_is_keymaker());
            g().reset();
            return mlab::result_success;
        }


    }// namespace v0

}// namespace ka::p2p

namespace mlab {
    bin_stream &operator>>(bin_stream &s, ka::p2p::gate_fw_info &fwinfo) {
        s >> fwinfo.semantic_version;
        s >> length_encoded >> fwinfo.commit_info;
        s >> length_encoded >> fwinfo.app_name;
        s >> length_encoded >> fwinfo.platform_code;
        s >> fwinfo.proto_version;
        return s;
    }

    bin_data &operator<<(bin_data &bd, ka::p2p::gate_fw_info const &fwinfo) {
        return bd << fwinfo.semantic_version
                  << length_encoded << fwinfo.commit_info
                  << length_encoded << fwinfo.app_name
                  << length_encoded << fwinfo.platform_code
                  << fwinfo.proto_version;
    }

    bin_stream &operator>>(bin_stream &s, ka::p2p::v0::gate_registration_info &rinfo) {
        s >> rinfo.id >> rinfo.pk >> rinfo.keymaker_pk;
        return s;
    }

    bin_data &operator<<(bin_data &bd, ka::p2p::v0::gate_registration_info const &rinfo) {
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

    bin_stream &operator>>(bin_stream &s, ka::p2p::v0::update_config &usettings) {
        s >> length_encoded >> usettings.update_channel >> usettings.enable_automatic_update;
        return s;
    };

    bin_data &operator<<(bin_data &bd, ka::p2p::v0::update_config const &usettings) {
        return bd << length_encoded << usettings.update_channel << usettings.enable_automatic_update;
    }

    bin_stream &operator>>(bin_stream &s, ka::p2p::v0::wifi_status &wfsettings) {
        s >> length_encoded >> wfsettings.ssid >> wfsettings.operational;
        return s;
    }

    bin_stream &operator>>(bin_stream &s, ka::release_info &ri) {
        s >> ri.semantic_version >> length_encoded >> ri.firmware_url;
        return s;
    }

    bin_data &operator<<(bin_data &bd, ka::release_info const &ri) {
        return bd << ri.semantic_version << length_encoded << ri.firmware_url;
    }

    bin_data &operator<<(bin_data &bd, ka::p2p::v0::wifi_status const &wfsettings) {
        return bd << length_encoded << wfsettings.ssid << wfsettings.operational;
    }

    bin_data &operator<<(encode_length<bin_data> w, std::string_view s) {
        return w.s << mlab::lsb32 << s.size() << mlab::data_from_string(s);
    }

    bin_stream &operator>>(encode_length<bin_stream> w, std::string &str) {
        auto &s = w.s;
        if (s.bad() or s.remaining() < 4) {
            s.set_bad();
            return s;
        }
        std::uint32_t length = 0;
        s >> mlab::lsb32 >> length;
        if (s.bad()) {
            return s;
        }
        if (s.remaining() < length) {
            s.set_bad();
            return s;
        }
        str = mlab::data_to_string(s.read(length));
        return s;
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