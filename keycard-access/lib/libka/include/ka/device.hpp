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
        key_pair _kp = {};
        std::unique_ptr<ota_watch> _ota = nullptr;
        std::shared_ptr<nvs::namespc> _device_ns = nullptr;

        device() = default;

        void generate_keys();

    protected:
        [[nodiscard]] inline key_pair const &keys() const;

    public:
        /**
         * Construct a device loading it from the NVS partition. All changes will be persisted.
         */
        explicit device(std::shared_ptr<nvs::partition> const &partition);

        /**
         * Construct a device the given key pair. Testing purposes, changes will not be persisted
         * and updates are not available on the device.
         */
        explicit device(key_pair kp);

        virtual ~device() = default;

        device(device const &) = delete;
        device(device &&) = default;
        device &operator=(device const &) = delete;
        device &operator=(device &&) = default;

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

        virtual void register_commands(cmd::shell &sh);
    };
}// namespace ka

namespace ka {
    const key_pair &device::keys() const {
        return _kp;
    }
}

#endif//KEYCARD_ACCESS_DEVICE_HPP
