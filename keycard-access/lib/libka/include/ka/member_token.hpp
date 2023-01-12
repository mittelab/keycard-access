//
// Created by spak on 9/29/22.
//

#ifndef KEYCARDACCESS_MEMBER_TOKEN_HPP
#define KEYCARDACCESS_MEMBER_TOKEN_HPP

#include <ka/config.hpp>
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

        [[nodiscard]] r<identity, bool> verify_ticket(desfire::app_id aid, desfire::file_id fid, ticket const &t) const;
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

        /**
         * To be run by the programmer. Creates a new app for the gate and installs a ticket on @ref gate_enroll_file,
         * which certifies for the current @ref identity. The ticket is then returned and should be transmitted securely
         * to the gate, which can then use it to certify the authenticity of the card and the identity of the holder.
         * @note This method will wipe the gate app, and requires a valid root password.
         * @param gid
         * @param gkey
         * @return
         */
        [[nodiscard]] r<ticket> install_enroll_ticket(gate_id gid);

        /**
         * To be run by the programmer. Verifies the ticket @p t, which should be the output of  @ref install_enroll_ticket,
         * and certifies the authenticity of the card and the identity of the holder.
         * @note This does not require the root password.
         * @param gid
         * @param ticket
         * @return
         */
        [[nodiscard]] r<bool> verify_enroll_ticket(gate_id gid, ticket const &enroll_ticket) const;

        /**
         * To be run by the gate.
         * @note This method does not require the root password.
         * @param gid
         * @param verified_enroll_ticket
         * @param auth_ticket
         * @return
         */
        r<> switch_enroll_to_auth_ticket(gate_id gid, ticket const &verified_enroll_ticket, ticket const &auth_ticket);

        /**
         * To be run by the gate. Verifies the ticket @p t, which was previously installed via @ref install_auth_ticket,
         * and certifies the authenticity of the card and the identity of the holder.
         * @note This does not require the root password.
         * @param gid
         * @param auth_ticket
         * @return
         */
        [[nodiscard]] r<bool> verify_auth_ticket(gate_id gid, ticket const &auth_ticket) const;

        /**
         * @brief Fast-lane authentication method.
         * This method is analogous to @ref verify_auth_ticket but will return the identity that was certified.
         * If the identity cannot be certified, @ref desfire::error::authentication_error will be returned.
         * @note This does not require the root password.
         * @param gid
         * @param auth_ticket
         * @return
         */
        [[nodiscard]] r<identity> authenticate(gate_id gid, ticket const &auth_ticket) const;

        /**
         * @note This does not require a valid root password.
         * @param gid
         * @return
         */
        [[nodiscard]] r<gate_status> get_gate_status(gate_id gid) const;
        /**
          * @}
          */

        /**
         * @brief The ID of the token, as in @ref desfire::tag::get_card_uid().
         */
        [[nodiscard]] r<token_id> id() const;
    };

}// namespace ka

namespace ka {

    desfire::tag &member_token::tag() const {
        return *_tag;
    }

}// namespace ka

#endif//KEYCARDACCESS_MEMBER_TOKEN_HPP
