//
// Created by spak on 9/29/22.
//

#ifndef KEYCARDACCESS_MEMBER_TOKEN_HPP
#define KEYCARDACCESS_MEMBER_TOKEN_HPP

#include <ka/config.hpp>
#include <ka/key_manager.hpp>
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

        r<> install_ticket(desfire::app_id aid, desfire::file_id fid, app_master_key const &mkey, ticket const &t);
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

        [[nodiscard]] r<> try_set_root_key(token_root_key const &k);
        [[nodiscard]] r<> unlock();

        [[nodiscard]] inline desfire::tag &tag() const;

        [[nodiscard]] r<std::string> get_holder() const;
        [[nodiscard]] r<std::string> get_publisher() const;
        [[nodiscard]] r<identity> get_identity() const;
        [[nodiscard]] r<unsigned> get_mad_version() const;

        [[nodiscard]] r<std::vector<gate_id>> get_enrolled_gates() const;

        /**
         * @addtogroup Provisioning
         * @{
         */
        r<> setup_root(token_root_key const &rkey);
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
         * @note This method will wipe the gate app.
         * @param gid
         * @param gkey
         * @return
         */
        [[nodiscard]] r<ticket> install_enroll_ticket(gate_id gid, gate_app_master_key const &gkey);

        /**
         * To be run by the programmer. Verifies the ticket @p t, which should be the output of  @ref install_enroll_ticket,
         * and certifies the authenticity of the card and the identity of the holder.
         * @param gid
         * @param ticket
         * @return
         */
        [[nodiscard]] r<bool> verify_enroll_ticket(gate_id gid, ticket const &t) const;

        /**
         * To be run by the gate. Creates a new app for the gate and installs @p t on @ref gate_authentication_file,
         * which certifies for the current @ref identity. This is an enrollment operation which is intended to follow
         * a successful call to @ref verify_enroll_ticket: after asserting the identity and authenticity, a gate will
         * install its own file for future authentication.
         * @note This method will wipe the gate app.
         * @param gid
         * @param gkey
         * @param t
         * @return
         */
        r<> install_auth_ticket(gate_id gid, gate_app_master_key const &gkey, ticket const &t);

        /**
         * To be run by the gate. Verifies the ticket @p t, which was previously installed via @ref install_auth_ticket,
         * and certifies the authenticity of the card and the identity of the holder.
         * @param gid
         * @param t
         * @return
         */
        [[nodiscard]] r<bool> verify_auth_ticket(gate_id gid, ticket const &t) const;

        /**
         * @brief Fast-lane authentication method.
         * This method is analoguous to @ref verify_auth_ticket but will return the identity that was certified.
         * If the identity cannot be certified, @ref desfire::error::authentication_error will be returned.
         * @param gid
         * @param t
         * @return
         */
        [[nodiscard]] r<identity> authenticate(gate_id gid, ticket const &t) const;

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
