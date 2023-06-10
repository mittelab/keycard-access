//
// Created by spak on 6/1/23.
//

#ifndef KEYCARD_ACCESS_WIFI_HPP
#define KEYCARD_ACCESS_WIFI_HPP

#include <chrono>
#include <condition_variable>

namespace ka {
    namespace {
        using namespace std::chrono_literals;
    }

    enum struct wifi_status {
        idle = 0,
        connecting,
        getting_ip,
        ready,
        failure
    };

    [[nodiscard]] constexpr bool wifi_status_is_on(wifi_status ws);

    class wifi {
        class wifi_impl;
        static void wifi_impl_deleter(wifi_impl *wi);

        /**
         * @note An opaque pointer, with a custom deleter so that the size of @ref wifi_impl needs not to be known.
         */
        std::unique_ptr<wifi_impl, void (*)(wifi_impl *)> _pimpl;

    public:
        wifi();

        wifi(std::string const &ssid, std::string const &pass, bool auto_connect = true);

        void reconfigure(std::string const &ssid, std::string const &pass, bool auto_connect = true);

        void connect();

        void disconnect();

        [[nodiscard]] wifi_status status() const;

        wifi_status await_status_change(wifi_status old, std::chrono::milliseconds timeout = 30s);

        [[nodiscard]] bool await_connection_attempt(std::chrono::milliseconds timeout = 30s);

        bool ensure_connected(std::chrono::milliseconds timeout = 30s);

        [[nodiscard]] unsigned attempts() const;

        [[nodiscard]] unsigned max_attempts() const;

        void set_max_attempts(unsigned n);
    };
}// namespace ka

namespace ka {
    constexpr bool wifi_status_is_on(wifi_status ws) {
        switch (ws) {
            case wifi_status::idle:
                [[fallthrough]];
            case wifi_status::failure:
                return false;
            default:
                return true;
        }
    }
}// namespace ka

#endif//KEYCARD_ACCESS_WIFI_HPP
