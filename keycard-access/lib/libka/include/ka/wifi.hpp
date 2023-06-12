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

    class wifi_session {
        wifi *_wf = nullptr;
        bool _disconnect_when_done = true;
    public:
        wifi_session() = default;
        explicit wifi_session(wifi &wf, std::chrono::milliseconds timeout = 30s);
        wifi_session(wifi &wf, bool disconnect_when_done, std::chrono::milliseconds timeout = 30s);

        wifi_session(wifi_session const &) = delete;
        wifi_session &operator=(wifi_session const &) = delete;

        wifi_session(wifi_session &&) = default;
        wifi_session &operator=(wifi_session &&) = default;

        /**
         * True if connected.
         */
        inline explicit operator bool() const;

        [[nodiscard]] inline bool disconnect_when_done() const;
        inline void set_disconnect_when_done(bool v);

        ~wifi_session();
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

    bool wifi_session::disconnect_when_done() const {
        return _disconnect_when_done;
    }
    void wifi_session::set_disconnect_when_done(bool v) {
        _disconnect_when_done = v;
    }
}// namespace ka

#endif//KEYCARD_ACCESS_WIFI_HPP
