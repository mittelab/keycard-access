//
// Created by spak on 9/29/22.
//

#ifndef KEYCARDACCESS_MEMBER_TOKEN_HPP
#define KEYCARDACCESS_MEMBER_TOKEN_HPP

#include <ka/config.hpp>
#include <ka/data.hpp>
#include <ka/gate.hpp>

namespace ka {

    class ticket;

    /**
     * @note Conventions: methods do perform authentication with the root key_type.
     */
    class member_token {
        /**
         * @note Mutable because interacting with the tag requires non-const access.
         */
        mutable desfire::tag *_tag;
        desfire::any_key _root_key;

    public:
        /**
         * @brief Application directory app id as required by AN10787 §3.10.
         */
        static constexpr desfire::app_id mad_aid{0xff, 0xff, 0xff};
        static constexpr desfire::file_id mad_file_version{0x0};
        static constexpr desfire::file_id mad_file_card_holder{0x1};
        static constexpr desfire::file_id mad_file_card_publisher{0x2};

        static constexpr desfire::file_id gate_enroll_file{0x00};
        static constexpr desfire::file_id gate_authentication_file{0x01};

        using id_t = std::array<std::uint8_t, 7>;

        explicit member_token(desfire::tag &tag);
        member_token(member_token const &) = delete;
        member_token(member_token &&) = default;
        member_token &operator=(member_token const &) = delete;
        member_token &operator=(member_token &&) = default;

        [[nodiscard]] inline desfire::any_key const &root_key() const;
        [[nodiscard]] r<> try_set_root_key(desfire::any_key k);
        [[nodiscard]] r<> unlock();

        [[nodiscard]] inline desfire::tag &tag() const;

        [[nodiscard]] r<std::string> get_holder() const;
        [[nodiscard]] r<std::string> get_publisher() const;
        [[nodiscard]] r<identity> get_identity() const;
        [[nodiscard]] r<unsigned> get_mad_version() const;

        [[nodiscard]] r<std::vector<gate::id_t>> get_enrolled_gates() const;

        /**
         * @addtogroup Provisioning
         * @{
         */
        r<> setup_root_settings(config const &cfg = system_config());
        r<> setup_mad(identity const &id);
        /**
         * @}
         */

        /**
         * @addtogroup Enrollment
         * @{
         */
        /**
          * Creates a new app for this gate, controlled by the master key_type @p gate_key.
          * This app contains one file, at @ref gate_enroll_file, which is encrypted
          * with the returned key_type (randomly generated).
          * This file contains the hash of the current card holder @ref get_holder,
          * with a unique (randomly generated) salt, for increased security.
          * At this point, without the returned @ref ticket, cloning or forging
          * the card requires to break the card crypto.
          * @note Using a randomized key_type with a known file content would be enough to
          * prevent cloning or forging, but in this way we can verify that the card
          * has not been reassigned. By hashing we keep the file size under control, and
          * by adding a salt we strengthen the amount of random bits that need to be guessed.
          */
        r<ticket> install_enroll_ticket(gate::id_t gid, key_type const &gate_app_key);
        r<bool> verify_enroll_ticket(gate::id_t gid, ticket const &ticket) const;


        r<> write_auth_file(gate::id_t gid, key_type const &auth_file_key, std::string const &identity);
        r<bool> authenticate(gate::id_t gid, key_type const &auth_file_key, std::string const &identity) const;
        r<gate_status> get_gate_status(gate::id_t gid) const;
        /**
          * @}
          */

        /**
         * @brief The ID of the token, as in @ref desfire::tag::get_card_uid().
         */
        [[nodiscard]] r<id_t> id() const;

        /**
         * @brief A differentiated root key_type to be used with a token.
         * Note that we do not use a pre-shared key_type for this, rather, we simply derive an
         * token-specific key_type to differentiate from @ref config::master_key. The user is free to
         * tamper with their token. In the worst case, they might delete the access application
         * and need a redeploy.
         * This uses @ref desfire::kdf_an10922 to differentiate @ref config::master_key into a token-specific
         * root key_type. It uses the @p token_id and @ref config::differentiation_salt as differentiation input data.
         * @param token_id Id of the token
         * @param cfg Current configuration
         * @return A key_type which gives root access to the card.
         */
        [[nodiscard]] static key_type get_default_root_key(id_t token_id, config const &cfg = system_config());
    };

}// namespace ka

namespace ka {

    desfire::tag &member_token::tag() const {
        return *_tag;
    }

    desfire::any_key const &member_token::root_key() const {
        return _root_key;
    }

}// namespace ka

#endif//KEYCARDACCESS_MEMBER_TOKEN_HPP
