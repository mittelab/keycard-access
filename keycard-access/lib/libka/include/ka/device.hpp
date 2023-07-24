//
// Created by spak on 6/14/23.
//

#ifndef KEYCARD_ACCESS_DEVICE_HPP
#define KEYCARD_ACCESS_DEVICE_HPP

#include <ka/key_pair.hpp>
#include <ka/nvs.hpp>
#include <ka/ota.hpp>
#include <ka/wifi.hpp>

namespace ut {
    struct secure_p2p_loopback;
}

namespace ka {
    namespace cmd {
        class shell;
        template <class>
        struct parser;
    }// namespace cmd

    struct update_status {
        std::optional<std::string> updating_from = std::nullopt;
    };

    class device_keypair_storage {
        std::shared_ptr<nvs::namespc> _ns = nullptr;
    public:
        explicit device_keypair_storage(std::shared_ptr<nvs::namespc> ns);

        [[nodiscard]] std::optional<key_pair> load(std::string_view password);
        void save(key_pair const &kp, std::string_view password);
        [[nodiscard]] bool exists();
    };

    class device {
        key_pair _kp = {};
        std::unique_ptr<ota_watch> _ota = nullptr;
        std::shared_ptr<nvs::namespc> _device_ns = nullptr;

        device() = default;


        friend struct ut::secure_p2p_loopback;

    protected:
        [[nodiscard]] inline key_pair const &keys() const;

        void setup_ns_and_ota(std::shared_ptr<nvs::partition> const &partition);
        void generate_keys();
        void load_or_generate_keys();

    public:
        /**
         * Construct a device loading it from the NVS partition. All changes will be persisted.
         */
        explicit device(std::shared_ptr<nvs::partition> const &partition);

        /**
         * Construct a device loading it from the NVS, but using password hashing for the key pair.
         * All changes but the key pair will be persisted.
         */
        explicit device(std::shared_ptr<nvs::partition> const &partition, std::string_view password);

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
        void update_now();
        void update_manually(std::string_view fw_url);
        [[nodiscard]] update_status is_updating() const;

        [[nodiscard]] bool wifi_is_configured() const;
        [[nodiscard]] std::optional<std::string> wifi_get_ssid() const;
        [[nodiscard]] bool wifi_test();
        bool wifi_connect(std::string_view ssid, std::string_view password);

        virtual void register_commands(cmd::shell &sh);
    };

    namespace cmd {
        template <>
        struct parser<update_status> {
            [[nodiscard]] static std::string to_string(update_status const &us);
        };
        template <>
        struct parser<release_info> {
            [[nodiscard]] static std::string to_string(release_info const &ri);
        };
    }// namespace cmd
}// namespace ka

namespace ka {
    const key_pair &device::keys() const {
        return _kp;
    }
}// namespace ka

#endif//KEYCARD_ACCESS_DEVICE_HPP
