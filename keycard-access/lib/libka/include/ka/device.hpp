//
// Created by spak on 6/14/23.
//

#ifndef KEYCARD_ACCESS_DEVICE_HPP
#define KEYCARD_ACCESS_DEVICE_HPP

#include <ka/key_pair.hpp>
#include <ka/nvs.hpp>
#include <ka/ota.hpp>
#include <ka/wifi.hpp>

namespace ka {
    namespace cmd {
        class shell;
    }

    class device {
        key_pair _kp;
        ota_watch _ota;
        std::shared_ptr<nvs::namespc> _device_ns;

        void configure();

    public:
        device();

        device(device const &) = delete;
        device(device &&) = delete;
        device &operator=(device const &) = delete;
        device &operator=(device &&) = delete;

        [[nodiscard]] bool updates_automatically() const;
        void set_update_automatically(bool v);

        [[nodiscard]] std::string_view update_channel() const;
        bool set_update_channel(std::string_view channel, bool test_before);

        [[nodiscard]] std::optional<release_info> check_for_updates() const;
        [[nodiscard]] fw_info get_firmware_info() const;
        void update_firmware();
        void update_firmware(std::string_view fw_url);

        [[nodiscard]] bool is_wifi_configured() const;
        [[nodiscard]] std::optional<std::string> get_wifi_ssid() const;
        [[nodiscard]] bool test_wifi();
        bool connect_wifi(std::string_view ssid, std::string_view password);

        void register_commands(cmd::shell &sh);
    };
}// namespace ka

#endif//KEYCARD_ACCESS_DEVICE_HPP
