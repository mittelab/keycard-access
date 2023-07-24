//
// Created by spak on 6/1/23.
//

#ifndef KEYCARD_ACCESS_WIFI_HPP
#define KEYCARD_ACCESS_WIFI_HPP

#include <chrono>
#include <condition_variable>
#include <esp_wifi_types.h>
#include <mutex>
#include <optional>

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
        //// FreeRTOS event group to signal when we are connected
        esp_event_handler_instance_t _instance_any_id;
        esp_event_handler_instance_t _instance_got_ip;
        std::atomic<unsigned> _attempts;
        std::atomic<unsigned> _max_attempts;
        std::atomic<wifi_status> _status;
        std::recursive_mutex _mutex;
        std::condition_variable _status_change;
        std::mutex _status_change_mutex;
        bool _is_started;

        static void wifi_event_handler(void *context, esp_event_base_t event_base, std::int32_t event_id, void *event_data);

        void handle_wifi_event(esp_event_base_t event_base, std::int32_t event_id, void *event_data);

        void configure_internal(std::string_view ssid, std::string_view pass);

        wifi();

    public:
        wifi(wifi const &) = delete;
        wifi(wifi &&) = delete;
        wifi &operator=(wifi const &) = delete;
        wifi &operator=(wifi &&) = delete;

        ~wifi();

        void reconfigure(std::string_view ssid, std::string_view pass, bool auto_connect = true);

        void connect();

        void disconnect();

        [[nodiscard]] wifi_status status() const;

        wifi_status await_status_change(wifi_status old, std::chrono::milliseconds timeout = 30s);

        [[nodiscard]] bool await_connection_attempt(std::chrono::milliseconds timeout = 30s);

        bool ensure_connected(std::chrono::milliseconds timeout = 30s);

        [[nodiscard]] unsigned attempts() const;

        [[nodiscard]] unsigned max_attempts() const;

        [[nodiscard]] std::optional<std::string> get_ssid() const;

        void set_max_attempts(unsigned n);

        [[nodiscard]] static wifi &instance();
    };

    enum wifi_session_usage {
        as_found,
        leave_on,
        disconnect
    };

    class wifi_session {
        bool _disconnect_when_done = true;
        wifi_ps_type_t _orig_ps_mode = WIFI_PS_MIN_MODEM;

    public:
        explicit wifi_session(std::chrono::milliseconds timeout = 10s, wifi_session_usage usage = wifi_session_usage::as_found);

        wifi_session(wifi_session const &) = delete;
        wifi_session &operator=(wifi_session const &) = delete;

        wifi_session(wifi_session &&) = default;
        wifi_session &operator=(wifi_session &&) = default;

        /**
         * True if connected.
         */
        explicit operator bool() const;

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
}// namespace ka

#endif//KEYCARD_ACCESS_WIFI_HPP
