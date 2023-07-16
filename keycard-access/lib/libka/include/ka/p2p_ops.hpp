//
// Created by spak on 1/20/23.
//

#ifndef KEYCARD_ACCESS_P2P_OPS_HPP
#define KEYCARD_ACCESS_P2P_OPS_HPP

#include <ka/data.hpp>
#include <ka/key_pair.hpp>
#include <pn532/p2p.hpp>

namespace ka {
    class gate;
    struct gate_pub_info;
}// namespace ka

namespace semver {
    struct version;
}

namespace ka::p2p {
    class secure_target;
    class secure_initiator;

    enum struct error : std::uint8_t {
        malformed,           ///< Command is malformed or unsupported
        unauthorized,        ///< This keymaker is not allowed to issue this command.
        invalid,             ///< Cannot execute this command in the current state.
        arg_error,           ///< Invalid argument
        p2p_timeout = 0xfc,  ///< The given timeout was exceeded before the transmission was complete.
        p2p_hw_error = 0xfd, ///< Hardware error during transmission.
        p2p_malformed = 0xfe,///< Malformed data cannot be parsed, or the type of frame received was unexpected.
        p2p_app_error = 0xff,///< The PN532 gave an application-level ERROR frame.
    };

    [[nodiscard]] const char *to_string(error e);

    [[nodiscard]] constexpr error channel_error_to_p2p_error(pn532::channel_error err);

    struct gate_fw_info : fw_info {
        std::uint8_t proto_version = 0;
    };

    template <class... Args>
    using r = mlab::result<error, Args...>;

    [[nodiscard]] bool assert_stream_healthy(mlab::bin_stream const &s);

    /**
     * @note Since cards are targets, and the gate continuously operates searching for a target, the
     * keymaker must act as a target too so that the gate can see a keymaker is in the field.
     */
    class remote_gate_base {
        secure_target &_local_interface;

    protected:
        [[nodiscard]] inline secure_target &local_interface();
        [[nodiscard]] inline secure_target const &local_interface() const;

        [[nodiscard]] r<gate_fw_info> hello_and_assert_protocol(std::uint8_t proto_version);

        template <class R, class... Args>
        [[nodiscard]] std::conditional_t<std::is_void_v<R>, r<>, r<R>> command_parse_response(std::uint8_t command_code, Args &&...args);

        template <class R, mlab::is_byte_enum CmdCode, class... Args>
        [[nodiscard]] std::conditional_t<std::is_void_v<R>, r<>, r<R>> command_parse_response(CmdCode command_code, Args &&...args);

        [[nodiscard]] r<mlab::bin_data> command_response(std::uint8_t command_code, mlab::bin_data cmd);
        [[nodiscard]] r<> command(std::uint8_t command_code, mlab::bin_data cmd);

    public:
        /**
         * @param local_interface A secure target with already performed handshake.
         */
        explicit remote_gate_base(secure_target &local_interface);
        virtual ~remote_gate_base() = default;

        [[nodiscard]] virtual r<gate_fw_info> hello();
        virtual void bye();
    };

    enum struct proto_status : std::uint8_t {
        ok = 0x00,
        malformed,
        unauthorized,
        invalid,
        arg_error,
        ready_for_cmd = 0xfe,
        did_read_resp = 0xff
    };

    [[nodiscard]] error proto_status_to_error(proto_status s);
    [[nodiscard]] proto_status error_to_proto_status(error e);

    class local_gate_base {
        secure_initiator &_local_interface;
        gate &_g;

    protected:
        enum struct serve_outcome {
            ok,
            unknown,
            halt
        };

        [[nodiscard]] inline secure_initiator &local_interface();
        [[nodiscard]] inline secure_initiator const &local_interface() const;

        [[nodiscard]] inline gate &g();
        [[nodiscard]] inline gate const &g() const;

        [[nodiscard]] r<std::uint8_t, mlab::bin_data> command_receive();
        [[nodiscard]] r<> response_send(proto_status s, mlab::bin_data resp);

        template <class... Args>
        [[nodiscard]] r<> response_send(r<Args...> const &response);

        [[nodiscard]] r<> response_send(r<std::string> const &response);

        [[nodiscard]] virtual r<serve_outcome> try_serve_command(std::uint8_t command_code, mlab::bin_data const &body);
        [[nodiscard]] r<> assert_peer_is_keymaker() const;

    public:
        [[nodiscard]] virtual std::uint8_t protocol_version() const = 0;

        [[nodiscard]] virtual r<gate_fw_info> hello();
        [[nodiscard]] virtual r<gate_fw_info> hello(mlab::bin_data const &body);

        void serve_loop();

        explicit local_gate_base(secure_initiator &local_interface, gate &g);
        virtual ~local_gate_base() = default;
    };

    struct protocol_factory_base {
        [[nodiscard]] virtual std::unique_ptr<local_gate_base> operator()(secure_initiator &initiator, gate &g) const = 0;
        virtual ~protocol_factory_base() = default;
    };

    template <local_gate_protocol Protocol>
    struct protocol_factory final : protocol_factory_base {
        [[nodiscard]] std::unique_ptr<local_gate_base> operator()(secure_initiator &initiator, gate &g) const override {
            return std::make_unique<Protocol>(initiator, g);
        }
    };


    namespace v0 {
        struct gate_registration_info : ka::gate_pub_info {
            pub_key keymaker_pk;

            gate_registration_info() = default;
            gate_registration_info(gate_id id_, pub_key pk_, pub_key km_pk_) : gate_pub_info{id_, pk_}, keymaker_pk{km_pk_} {}
            gate_registration_info(gate_pub_info pi_, pub_key km_pk_) : gate_pub_info{pi_}, keymaker_pk{km_pk_} {}
        };

        struct update_config {
            std::string update_channel = {};
            bool enable_automatic_update = false;
        };

        struct wifi_status {
            /**
             * Empty = no SSID.
             */
            std::string ssid = {};
            bool operational = false;
        };

        class remote_gate : public remote_gate_base {
        public:
            using remote_gate_base::remote_gate_base;
            [[nodiscard]] r<gate_fw_info> hello() override;

            [[nodiscard]] virtual r<update_config> get_update_settings();
            [[nodiscard]] virtual r<> set_update_settings(std::string_view update_channel, bool automatic_updates);
            [[nodiscard]] virtual r<release_info> check_for_updates();
            [[nodiscard]] virtual r<update_status> is_updating();
            [[nodiscard]] virtual r<release_info> update_now();
            [[nodiscard]] virtual r<> update_manually(std::string_view fw_url);
            [[nodiscard]] virtual r<> set_backend_url(std::string_view url, std::string_view api_key);
            [[nodiscard]] virtual r<std::string> get_backend_url();
            /**
             * @todo Add set/get gpio config
             */
            [[nodiscard]] virtual r<wifi_status> get_wifi_status();
            [[nodiscard]] virtual r<bool> connect_wifi(std::string_view ssid, std::string_view password);
            [[nodiscard]] virtual r<gate_registration_info> get_registration_info();
            [[nodiscard]] virtual r<gate_base_key> register_gate(gate_id requested_id);
            [[nodiscard]] virtual r<> reset_gate();
        };

        class local_gate : public local_gate_base {
        protected:
            [[nodiscard]] r<serve_outcome> try_serve_command(std::uint8_t command_code, mlab::bin_data const &body) override;

            [[nodiscard]] virtual r<update_config> get_update_settings(mlab::bin_data const &body);
            [[nodiscard]] virtual r<> set_update_settings(mlab::bin_data const &body);
            [[nodiscard]] virtual r<release_info> check_for_updates(mlab::bin_data const &body);
            [[nodiscard]] virtual r<update_status> is_updating(mlab::bin_data const &body);
            [[nodiscard]] virtual r<release_info> update_now(mlab::bin_data const &body);
            [[nodiscard]] virtual r<> update_manually(mlab::bin_data const &body);
            [[nodiscard]] virtual r<> set_backend_url(mlab::bin_data const &body);
            [[nodiscard]] virtual r<std::string> get_backend_url(mlab::bin_data const &body);
            [[nodiscard]] virtual r<wifi_status> get_wifi_status(mlab::bin_data const &body);
            [[nodiscard]] virtual r<bool> connect_wifi(mlab::bin_data const &body);
            [[nodiscard]] virtual r<gate_registration_info> get_registration_info(mlab::bin_data const &body);
            [[nodiscard]] virtual r<gate_base_key> register_gate(mlab::bin_data const &body);
            [[nodiscard]] virtual r<> reset_gate(mlab::bin_data const &body);

        public:
            using local_gate_base::local_gate_base;

            [[nodiscard]] inline std::uint8_t protocol_version() const override { return 0; }
            [[nodiscard]] virtual r<update_config> get_update_settings();
            [[nodiscard]] virtual r<> set_update_settings(std::string_view update_channel, bool automatic_updates);
            [[nodiscard]] virtual r<wifi_status> get_wifi_status();
            [[nodiscard]] virtual r<release_info> check_for_updates();
            [[nodiscard]] virtual r<update_status> is_updating();
            [[nodiscard]] virtual r<release_info> update_now();
            [[nodiscard]] virtual r<> update_manually(std::string_view fw_url);
            [[nodiscard]] virtual r<> set_backend_url(std::string_view url, std::string_view api_key);
            [[nodiscard]] virtual r<std::string> get_backend_url();
            [[nodiscard]] virtual r<bool> connect_wifi(std::string_view ssid, std::string_view password);
            [[nodiscard]] virtual r<gate_registration_info> get_registration_info();
            [[nodiscard]] virtual r<gate_base_key> register_gate(gate_id requested_id);
            [[nodiscard]] virtual r<> reset_gate();
        };

    }// namespace v0

}// namespace ka::p2p

namespace mlab {

    struct length_encoded_t {};

    constexpr length_encoded_t length_encoded{};

    template <class T = bin_stream>
    struct encode_length {
        T &s;
    };

    inline encode_length<bin_stream> operator>>(bin_stream &s, length_encoded_t);
    inline encode_length<bin_data> operator<<(bin_data &bd, length_encoded_t);

    bin_stream &operator>>(bin_stream &s, ka::p2p::gate_fw_info &fwinfo);
    bin_stream &operator>>(bin_stream &s, ka::p2p::v0::gate_registration_info &rinfo);
    bin_stream &operator>>(bin_stream &s, semver::version &v);
    bin_stream &operator>>(encode_length<bin_stream> w, std::string &str);
    bin_stream &operator>>(bin_stream &s, ka::gate_id &gid);
    bin_stream &operator>>(bin_stream &s, ka::p2p::v0::update_config &usettings);
    bin_stream &operator>>(bin_stream &s, ka::p2p::v0::wifi_status &wfsettings);
    bin_stream &operator>>(bin_stream &s, ka::release_info &ri);
    bin_stream &operator>>(bin_stream &s, ka::update_status &us);

    bin_data &operator<<(bin_data &bd, ka::p2p::gate_fw_info const &fwinfo);
    bin_data &operator<<(bin_data &bd, ka::p2p::v0::gate_registration_info const &rinfo);
    bin_data &operator<<(bin_data &bd, semver::version const &v);
    bin_data &operator<<(encode_length<bin_data> w, std::string_view s);
    bin_data &operator<<(bin_data &bd, ka::gate_id const &gid);
    bin_data &operator<<(bin_data &bd, ka::p2p::v0::update_config const &usettings);
    bin_data &operator<<(bin_data &bd, ka::p2p::v0::wifi_status const &wfsettings);
    bin_data &operator<<(bin_data &bd, ka::release_info const &ri);
    bin_data &operator<<(bin_data &bd, ka::update_status const &us);
}// namespace mlab

namespace ka::p2p {

    secure_target &remote_gate_base::local_interface() {
        return _local_interface;
    }

    secure_target const &remote_gate_base::local_interface() const {
        return _local_interface;
    }

    secure_initiator &local_gate_base::local_interface() {
        return _local_interface;
    }

    secure_initiator const &local_gate_base::local_interface() const {
        return _local_interface;
    }

    gate &local_gate_base::g() {
        return _g;
    }

    gate const &local_gate_base::g() const {
        return _g;
    }

    constexpr error channel_error_to_p2p_error(pn532::channel_error err) {
        switch (err) {
            case pn532::channel_error::timeout:
                return error::p2p_timeout;
            default:
                [[fallthrough]];
            case pn532::channel_error::app_error:
                return error::p2p_app_error;
            case pn532::channel_error::hw_error:
                return error::p2p_hw_error;
            case pn532::channel_error::malformed:
                return error::p2p_malformed;
        }
    }

    template <class R, mlab::is_byte_enum CmdCode, class... Args>
    std::conditional_t<std::is_void_v<R>, r<>, r<R>> remote_gate_base::command_parse_response(CmdCode command_code, Args &&...args) {
        return command_parse_response<R, Args...>(static_cast<std::uint8_t>(command_code), std::forward<Args>(args)...);
    }

    namespace impl {
        template <std::size_t... Is, class... Args>
        [[nodiscard]] mlab::bin_data chain_result(std::index_sequence<Is...>, r<Args...> const &result) {
            mlab::bin_data bd;
            (bd << ... << mlab::get<Is>(result));
            return bd;
        }
    }// namespace impl

    template <class... Args>
    r<> local_gate_base::response_send(r<Args...> const &response) {
        if (not response) {
            return response_send(error_to_proto_status(response.error()), {});
        } else {
            if constexpr (sizeof...(Args) == 0) {
                return response_send(proto_status::ok, {});
            } else {
                return response_send(proto_status::ok, impl::chain_result(std::index_sequence_for<Args...>{}, response));
            }
        }
    }

    template <class R, class... Args>
    std::conditional_t<std::is_void_v<R>, r<>, r<R>> remote_gate_base::command_parse_response(std::uint8_t command_code, Args &&...args) {
        mlab::bin_data body{};
        if constexpr (sizeof...(Args) > 0) {
            body = mlab::bin_data::chain(std::forward<Args>(args)...);
        }
        if (const auto r = command_response(command_code, std::move(body)); r) {
            mlab::bin_stream s{*r};
            if constexpr (std::is_void_v<R>) {
                if (assert_stream_healthy(s)) {
                    return mlab::result_success;
                } else {
                    return error::malformed;
                }
            } else {
                R retval{};
                s >> retval;
                if (assert_stream_healthy(s)) {
                    return retval;
                } else {
                    return error::malformed;
                }
            }
        } else {
            return r.error();
        }
    }
}// namespace ka::p2p

namespace mlab {
    encode_length<bin_stream> operator>>(bin_stream &s, length_encoded_t) {
        return {s};
    }

    encode_length<bin_data> operator<<(bin_data &bd, length_encoded_t) {
        return {bd};
    }
}// namespace mlab

#endif//KEYCARD_ACCESS_P2P_OPS_HPP
