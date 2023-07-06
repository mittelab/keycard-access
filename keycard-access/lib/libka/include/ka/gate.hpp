//
// Created by spak on 10/1/22.
//

#ifndef KEYCARDACCESS_GATE_HPP
#define KEYCARDACCESS_GATE_HPP

#include <cstdint>
#include <desfire/data.hpp>
#include <ka/data.hpp>
#include <ka/device.hpp>
#include <ka/key_pair.hpp>
#include <ka/member_token.hpp>

namespace pn532 {
    class controller;
}

namespace ka {
    namespace nvs {
        class partition;
    }

    class gate;

    struct gate_base_key_tag {};

    struct gate_base_key : public mlab::tagged_array<gate_base_key_tag, 32> {
        [[nodiscard]] gate_token_key derive_token_key(token_id const &token_id, std::uint8_t key_no) const;
    };


    struct gate_credentials {
        pub_key gate_pub_key = {};
        gate_base_key app_base_key = {};
    };

    struct gate_config : gate_credentials {
        gate_id id{};
    };

    /**
     * @brief Class that reacts to authentication attempts.
     */
    struct gate_auth_responder {
        virtual void on_authentication_success(identity const &id) {}
        virtual void on_authentication_fail(desfire::error auth_error, bool might_be_tampering) {}

        virtual ~gate_auth_responder() = default;
    };

    /**
     * @brief Specialization of @ref member_token_responder and @ref gate_auth_responder which simply calls @ref gate::try_authenticate.
     * @note Remember to mark any subclass as `final`.
     */
    class gate_responder : public virtual member_token_responder, public virtual gate_auth_responder {
        gate &_g;

    public:
        explicit gate_responder(gate &g) : _g{g} {}

        /**
         * @addtogroup Default responder method implementations
         * These methods are implemented only so that who sees this header can glance over all available events.
         * The default implementation simply logs with the prefix "GATE".
         * @{
         */
        void on_authentication_success(identity const &id) override;
        void on_authentication_fail(desfire::error auth_error, bool might_be_tampering) override;
        void on_activation(pn532::scanner &scanner, pn532::scanned_target const &target) override;
        void on_release(pn532::scanner &scanner, pn532::scanned_target const &target) override;
        void on_leaving_rf(pn532::scanner &scanner, pn532::scanned_target const &target) override;
        void on_failed_scan(pn532::scanner &scanner, pn532::channel_error err) override;
        /**
         * @}
         */

        pn532::post_interaction interact_with_token(member_token &token) override;
    };

    class gate final : public device {
        gate_id _id = std::numeric_limits<gate_id>::max();
        pub_key _km_pk = {};
        gate_base_key _base_key = {};

        std::shared_ptr<nvs::namespc> _gate_ns = nullptr;

    public:
        /**
         * Construct a gate loading it from the NVS partition. All changes will be persisted.
         * @see device::device(std::shared_ptr<nvs::partition> const &)
         */
        explicit gate(std::shared_ptr<nvs::partition> const &partition);

        /**
         * Construct an unconfigured gate with the given key pair. Testing purposes, changes will not be persisted
         * and updates are not available on the device.
         * @see device::device(key_pair)
         */
        explicit gate(key_pair kp);

        /**
         * Construct a configured gate with the given parameters. Testing purposes, changes will not be persisted
         * and updates are not available on the device.
         * @see device::device(key_pair)
         */
        explicit gate(key_pair kp, gate_id gid, pub_key keymaker_pubkey, gate_base_key base_key);

        /**
         * Resets this gate to the original status, keeping wifi and update settings.
         * @warning This will render all cards with this gate enrolled unusable on this gate!
         * @todo In @ref keymaker, have a mechanism to realise a gate has been revoked and delete the app/file from the card.
         */
        void reset();

        /**
         * @return `nullopt` if this gate was already configured.
         */
        [[nodiscard]] std::optional<gate_base_key> configure(gate_id gid, pub_key keymaker_pubkey);

        [[nodiscard]] gate_token_key derive_token_key(token_id const &token_id, std::uint8_t key_no) const;

        [[nodiscard]] gate_id id() const;
        [[nodiscard]] bool is_configured() const;
        [[nodiscard]] pub_key const &keymaker_pk() const;

        /**
         * @todo Make private?
         */
        using device::keys;

        void try_authenticate(member_token &token, gate_auth_responder &responder) const;

        [[deprecated]] void log_public_gate_info() const;
    };
}// namespace ka

namespace ka {
}// namespace ka

#endif//KEYCARDACCESS_GATE_HPP
