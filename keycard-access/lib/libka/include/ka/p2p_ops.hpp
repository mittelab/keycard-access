//
// Created by spak on 1/20/23.
//

#ifndef KEYCARD_ACCESS_P2P_OPS_HPP
#define KEYCARD_ACCESS_P2P_OPS_HPP

#include <ka/gate.hpp>
#include <ka/key_pair.hpp>
#include <pn532/p2p.hpp>

namespace ka {
    class gate;
}// namespace ka

namespace semver {
    struct version;
}

namespace ka::p2p {
    class secure_target;
    class secure_initiator;

    enum struct error : std::uint8_t {
        malformed = 1,       ///< Command is malformed or unsupported
        unauthorized,        ///< This keymaker is not allowed to issue this command.
        invalid,             ///< Cannot execute this command in the current state.
        p2p_timeout = 0xfc,  ///< The given timeout was exceeded before the transmission was complete.
        p2p_hw_error = 0xfd, ///< Hardware error during transmission.
        p2p_malformed = 0xfe,///< Malformed data cannot be parsed, or the type of frame received was unexpected.
        p2p_app_error = 0xff,///< The PN532 gave an application-level ERROR frame.
    };

    [[nodiscard]] constexpr error channel_error_to_p2p_error(pn532::channel_error err);

    struct gate_fw_info : fw_info {
        std::uint8_t proto_version = 0;
    };

    template <class... Args>
    using r = mlab::result<error, Args...>;

    class remote_gate_base {
        secure_initiator &_remote_gate;

        [[nodiscard]] static bool assert_stream_healthy(mlab::bin_stream const &s);

    protected:
        [[nodiscard]] inline secure_initiator &remote();
        [[nodiscard]] inline secure_initiator const &remote() const;

        [[nodiscard]] r<gate_fw_info> hello_and_assert_protocol(std::uint8_t proto_version);

        template <class R, class... Args>
        [[nodiscard]] std::conditional_t<std::is_void_v<R>, r<>, r<R>> command_parse_response(Args &&...args);

        [[nodiscard]] r<mlab::bin_data> command_response(mlab::bin_data const &command);

    public:
        explicit remote_gate_base(secure_initiator &remote_gate);

        [[nodiscard]] pub_key gate_public_key() const;

        [[nodiscard]] virtual r<gate_fw_info> hello();
        virtual void bye();

        virtual ~remote_gate_base() = default;
    };

    namespace v0 {
        struct registration_info {
            gate_id id = std::numeric_limits<gate_id>::max();
            pub_key km_pk = {};
        };

        struct update_settings {
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

        struct remote_gate : remote_gate_base {
            using remote_gate_base::remote_gate_base;

            [[nodiscard]] r<gate_fw_info> hello() override;

            [[nodiscard]] virtual r<update_settings> get_update_settings();
            [[nodiscard]] virtual r<> set_update_settings(std::string_view update_channel, bool automatic_updates);

            [[nodiscard]] virtual r<wifi_status> get_wifi_status();
            [[nodiscard]] virtual r<bool> connect_wifi(std::string_view ssid, std::string_view password);

            [[nodiscard]] virtual r<registration_info> get_registration_info();
            [[nodiscard]] virtual r<> register_gate(gate_id requested_id);
            [[nodiscard]] virtual r<> reset_gate();
        };
    }// namespace v0

    pn532::result<> configure_gate_exchange(keymaker &km, secure_initiator &comm, std::string const &gate_description);
    pn532::result<> configure_gate_exchange(gate &g, secure_target &comm);

    [[nodiscard]] bool configure_gate_in_rf(pn532::controller &ctrl, gate &g);
    [[nodiscard]] bool configure_gate_in_rf(pn532::controller &ctrl, std::uint8_t logical_index, keymaker &km, std::string const &gate_description);

    void configure_gate_loop(pn532::controller &ctrl, gate &g);
    [[nodiscard]] bool configure_gate_loop(pn532::controller &ctrl, keymaker &km, std::string const &gate_description);

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
    bin_stream &operator>>(bin_stream &s, semver::version &v);
    bin_stream &operator>>(encode_length<bin_stream> w, std::string &str);
    bin_stream &operator>>(bin_stream &s, ka::gate_id &gid);
    bin_stream &operator>>(bin_stream &s, ka::raw_pub_key &pk);
    bin_stream &operator>>(bin_stream &s, ka::pub_key &pk);
    bin_stream &operator>>(bin_stream &s, ka::p2p::v0::registration_info &rinfo);
    bin_stream &operator>>(bin_stream &s, ka::p2p::v0::update_settings &usettings);
    bin_stream &operator>>(bin_stream &s, ka::p2p::v0::wifi_status &wfsettings);

    bin_data &operator<<(encode_length<bin_data> w, std::string_view s);
}// namespace mlab

namespace ka::p2p {

    secure_initiator &remote_gate_base::remote() {
        return _remote_gate;
    }

    secure_initiator const &remote_gate_base::remote() const {
        return _remote_gate;
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


    template <class R, class... Args>
    std::conditional_t<std::is_void_v<R>, r<>, r<R>> remote_gate_base::command_parse_response(Args &&...args) {
        if (const auto r = command_response(mlab::bin_data::chain(std::forward<Args>(args)...)); r) {
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
