//
// Created by spak on 1/20/23.
//

#ifndef KEYCARD_ACCESS_P2P_OPS_HPP
#define KEYCARD_ACCESS_P2P_OPS_HPP

#include <ka/data.hpp>
#include <ka/key_pair.hpp>
#include <ka/rpc.hpp>
#include <pn532/p2p.hpp>

namespace ka {
    class gate;
    struct gate_pub_info;
    struct gpio_responder_config;
}// namespace ka

namespace semver {
    struct version;
}

namespace ka::p2p {
    class secure_target;
    class secure_initiator;

    struct gate_update_config {
        std::string update_channel = {};
        bool enable_automatic_update = false;
    };

    struct gate_registration_info : ka::gate_pub_info {
        pub_key keymaker_pk;

        gate_registration_info() = default;
        gate_registration_info(gate_id id_, pub_key pk_, pub_key km_pk_) : gate_pub_info{id_, pk_}, keymaker_pk{km_pk_} {}
        gate_registration_info(gate_pub_info pi_, pub_key km_pk_) : gate_pub_info{pi_}, keymaker_pk{km_pk_} {}
    };

    struct gate_wifi_status {
        /**
         * Empty = no SSID.
         */
        std::string ssid = {};
        bool operational = false;
    };

    namespace v2 {

        enum struct error : std::uint8_t {
            unauthorized = 0,
            invalid_argument,
            invalid_operation
        };

        [[nodiscard]] const char *to_string(error e);

        template <class... Args>
        using r = mlab::result<error, Args...>;

        class local_gate {
            gate &_g;
            std::shared_ptr<secure_initiator> _sec_layer;
            rpc::bridge _b;

            [[nodiscard]] r<> assert_peer_is_keymaker(bool allow_unconfigured = false) const;
            [[nodiscard]] pub_key peer_pub_key() const;

        public:
            explicit local_gate(gate &g, std::shared_ptr<secure_initiator> initiator);

            void serve_loop();

            /**
             * @addtogroup RemoteMethods
             * @{
             */

            [[nodiscard]] fw_info get_fw_info() const;
            [[nodiscard]] gate_update_config get_update_settings() const;
            [[nodiscard]] gate_wifi_status get_wifi_status() const;
            [[nodiscard]] update_status is_updating() const;
            [[nodiscard]] gpio_responder_config get_gpio_config() const;
            [[nodiscard]] std::string get_backend_url() const;
            [[nodiscard]] gate_registration_info get_registration_info() const;

            [[nodiscard]] r<release_info> check_for_updates();
            [[nodiscard]] r<gate_base_key> register_gate(gate_id requested_id);

            r<> set_update_settings(std::string_view update_channel, bool automatic_updates);
            r<> update_manually(std::string_view fw_url);
            r<> set_backend_url(std::string_view url, std::string_view api_key);
            r<> set_gpio_config(gpio_responder_config cfg);
            r<> reset_gate();
            r<release_info> update_now();
            r<bool> connect_wifi(std::string_view ssid, std::string_view password);

            void disconnect();

            /**
             * @}
             */
        };

        class remote_gate {
            std::shared_ptr<secure_target> _sec_layer;
            mutable rpc::bridge _b;

        public:
            explicit remote_gate(std::shared_ptr<secure_target> target);

            /**
             * @addtogroup RemoteMethods
             * @{
             */

            [[nodiscard]] rpc::r<fw_info> get_fw_info() const;
            [[nodiscard]] rpc::r<gate_update_config> get_update_settings() const;
            [[nodiscard]] rpc::r<gate_wifi_status> get_wifi_status() const;
            [[nodiscard]] rpc::r<update_status> is_updating() const;
            [[nodiscard]] rpc::r<gpio_responder_config> get_gpio_config() const;
            [[nodiscard]] rpc::r<std::string> get_backend_url() const;
            [[nodiscard]] rpc::r<gate_registration_info> get_registration_info() const;

            [[nodiscard]] rpc::r<r<release_info>> check_for_updates();
            [[nodiscard]] rpc::r<r<gate_base_key>> register_gate(gate_id requested_id);

            rpc::r<r<>> set_update_settings(std::string_view update_channel, bool automatic_updates);
            rpc::r<r<>> update_manually(std::string_view fw_url);
            rpc::r<r<>> set_backend_url(std::string_view url, std::string_view api_key);
            rpc::r<r<>> set_gpio_config(gpio_responder_config cfg);
            rpc::r<r<>> reset_gate();
            rpc::r<r<release_info>> update_now();
            rpc::r<r<bool>> connect_wifi(std::string_view ssid, std::string_view password);

            rpc::r<> bye();
            /**
             * @}
             */
        };
    }// namespace v2
}// namespace ka::p2p

namespace mlab {
    bin_stream &operator>>(bin_stream &s, ka::fw_info &fwinfo);
    bin_stream &operator>>(bin_stream &s, ka::p2p::gate_registration_info &rinfo);
    bin_stream &operator>>(bin_stream &s, semver::version &v);
    bin_stream &operator>>(bin_stream &s, ka::gate_id &gid);
    bin_stream &operator>>(bin_stream &s, ka::p2p::gate_update_config &usettings);
    bin_stream &operator>>(bin_stream &s, ka::p2p::gate_wifi_status &wfsettings);
    bin_stream &operator>>(bin_stream &s, ka::release_info &ri);
    bin_stream &operator>>(bin_stream &s, ka::update_status &us);

    bin_data &operator<<(bin_data &bd, ka::fw_info const &fwinfo);
    bin_data &operator<<(bin_data &bd, ka::p2p::gate_registration_info const &rinfo);
    bin_data &operator<<(bin_data &bd, semver::version const &v);
    bin_data &operator<<(bin_data &bd, ka::gate_id const &gid);
    bin_data &operator<<(bin_data &bd, ka::p2p::gate_update_config const &usettings);
    bin_data &operator<<(bin_data &bd, ka::p2p::gate_wifi_status const &wfsettings);
    bin_data &operator<<(bin_data &bd, ka::release_info const &ri);
    bin_data &operator<<(bin_data &bd, ka::update_status const &us);
}// namespace mlab


#endif//KEYCARD_ACCESS_P2P_OPS_HPP
