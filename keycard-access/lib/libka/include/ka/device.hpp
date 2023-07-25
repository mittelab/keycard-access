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
    class console;

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
        explicit device_keypair_storage(nvs::partition &partition);

        /**
         * This will not save anything, fail to load and claim no key exist.
         */
        device_keypair_storage() = default;

        [[nodiscard]] std::optional<key_pair> load(std::string_view password) const;
        void save(key_pair const &kp, std::string_view password);
        [[nodiscard]] bool exists() const;

        /**
         * @warning Will return std::nullopt even if @p allow_cancel is set to false, in the event that @p expected_kp differs from the stored one,
         * even if the password is correct.
         */
        [[nodiscard]] std::optional<std::string> prompt_for_password(console &c, bool allow_cancel, std::optional<key_pair> expected_kp = std::nullopt) const;
        [[nodiscard]] static std::optional<std::string> prompt_for_new_password(console &c, bool allow_cancel, bool exit_on_mismatch);
    };

    class device {
        device_keypair_storage _kp_storage;
        key_pair _kp;
        std::shared_ptr<nvs::namespc> _device_ns;
        std::unique_ptr<ota_watch> _ota;

        friend struct ut::secure_p2p_loopback;

        void restore_kp(std::string_view password);
        void restore_ota();

    protected:
        [[nodiscard]] inline key_pair const &keys() const;

        void regenerate_keys(std::string_view password);

    public:
        /**
         * Constructs a device loading all data but the key pair @p kp from the NVS partition. All changes will be persisted.
         */
        explicit device(nvs::partition &partition, device_keypair_storage kp_storage, key_pair kp);

        /**
         * Construct a device loading it from the NVS partition, including the password-protected key pair. All changes will be persisted.
         */
        explicit device(nvs::partition &partition, std::string_view password);

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

        void restart();

        [[nodiscard]] bool change_password_prompt();

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
