//
// Created by spak on 9/29/22.
//

#ifndef KEYCARDACCESS_MEMBER_TOKEN_HPP
#define KEYCARDACCESS_MEMBER_TOKEN_HPP

#include <ka/data.hpp>
#include <desfire/tag_responder.hpp>
#include <desfire/esp32/cipher_provider.hpp>

namespace ka {

    class member_token;

    /**
     * @brief Specialization of a token responder which casts a @ref desfire::tag into a @ref member_token
     */
    struct member_token_responder : public virtual desfire::tag_responder<desfire::esp32::default_cipher_provider> {
        pn532::post_interaction interact_with_tag(desfire::tag &tag) override;

        virtual pn532::post_interaction interact_with_token(member_token &token) = 0;
    };

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

        static constexpr desfire::file_id gate_authentication_file{0x00};

        explicit member_token(desfire::tag &tag);
        member_token(member_token const &) = delete;
        member_token(member_token &&) = default;
        member_token &operator=(member_token const &) = delete;
        member_token &operator=(member_token &&) = default;

        /**
         * @addtogroup RootPasswordManagement
         * @{
         */
        [[nodiscard]] r<> try_set_root_key(token_root_key const &k);
        [[nodiscard]] r<> unlock_root() const;
        /**
         * @}
         */

        [[nodiscard]] inline desfire::tag &tag() const;

        /**
         * @addtogroup ApplicationDirectory
         * @note This does not require a valid root password.
         * @{
         */
        [[nodiscard]] r<std::string> get_holder() const;
        [[nodiscard]] r<std::string> get_publisher() const;
        [[nodiscard]] r<identity> get_identity() const;
        [[nodiscard]] r<unsigned> get_mad_version() const;
        [[nodiscard]] r<token_id> get_id() const;
        /**
         * @}
         */

        /**
         * @note This requires a valid root password.
         * @return
         */
        [[nodiscard]] r<std::vector<gate_id>> get_enrolled_gates() const;

        /**
         * @addtogroup Provisioning
         * @{
         */
        /**
         * @note This requires a valid root password.
         * @param rkey
         * @return
         */
        r<> setup_root(token_root_key const &rkey);

        /**
         * @note This requires a valid root password.
         * @param id
         * @return
         */
        r<> setup_mad(identity const &id);
        /**
         * @}
         */

        /**
         * @addtogroup Enrollment
         * @{
         */

        r<> enroll_gate(gate_id gid, gate_app_master_key const &mkey, identity const &id);
        /**
         *
         * @param gid
         * @param mkey
         * @return @ref desfire::error::file_integrity_error for mismatch identity, @ref desfire::error::length_error for tampering with the hash.
         */
        [[nodiscard]] r<identity> authenticate(gate_id gid, gate_app_master_key const &mkey) const;

        [[nodiscard]] r<bool> is_gate_enrolled(gate_id gid) const;

        /**
          * @}
          */

    };

}// namespace ka

namespace ka {

    desfire::tag &member_token::tag() const {
        return *_tag;
    }

}// namespace ka

#endif//KEYCARDACCESS_MEMBER_TOKEN_HPP
