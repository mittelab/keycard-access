//
// Created by spak on 10/1/22.
//

#ifndef KEYCARDACCESS_GATE_HPP
#define KEYCARDACCESS_GATE_HPP

#include <cstdint>
#include <desfire/data.hpp>
#include <ka/data.hpp>
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

    struct gate_base_key : public tagged_array<gate_base_key_tag, 32> {
        [[nodiscard]] gate_token_key derive_token_key(token_id const &token_id, std::uint8_t key_no) const;
    };

    struct gate_config {
        gate_id id{};
        pub_key gate_pub_key;
        gate_base_key app_base_key{};
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
        void on_failed_scan(pn532::scanner &scanner, pn532::channel::error err) override;
        /**
         * @}
         */

        pn532::post_interaction interact_with_token(member_token &token) override;
    };

    class keyed_gate_locator;

    class gate {
    public:
        gate() = default;
        gate(gate const &) = delete;
        gate(gate &&) = default;
        gate &operator=(gate const &) = delete;
        gate &operator=(gate &&) = default;

        [[nodiscard]] inline bool is_configured() const;
        [[nodiscard]] inline key_pair keys() const;
        [[nodiscard]] inline pub_key programmer_pub_key() const;
        [[nodiscard]] inline std::string description() const;
        [[nodiscard]] inline gate_id id() const;
        [[nodiscard]] inline gate_base_key app_base_key() const;

        void regenerate_keys();
        void configure(gate_id id, std::string desc, pub_key prog_pub_key);

        void config_store(nvs::partition &partition) const;
        [[nodiscard]] bool config_load(nvs::partition &partition);
        static void config_clear(nvs::partition &partition);

        void config_store() const;
        [[nodiscard]] bool config_load();
        static void config_clear();

        [[nodiscard]] static gate load_from_config(nvs::partition &partition);
        [[nodiscard]] static gate load_from_config();

        void try_authenticate(member_token &token, gate_auth_responder &responder) const;

        void log_public_gate_info() const;

    private:
        gate_id _id = std::numeric_limits<gate_id>::max();
        std::string _desc;
        key_pair _kp;
        pub_key _prog_pk;
        gate_base_key _base_key{};
    };
}// namespace ka

namespace ka {
    bool gate::is_configured() const {
        return _id != std::numeric_limits<gate_id>::max();
    }
    key_pair gate::keys() const {
        return _kp;
    }
    pub_key gate::programmer_pub_key() const {
        return _prog_pk;
    }
    std::string gate::description() const {
        return _desc;
    }
    gate_id gate::id() const {
        return _id;
    }

    gate_base_key gate::app_base_key() const {
        return _base_key;
    }

}// namespace ka

#endif//KEYCARDACCESS_GATE_HPP
