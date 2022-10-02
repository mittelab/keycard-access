//
// Created by spak on 9/29/22.
//

#ifndef KEYCARDACCESS_MEMBER_TOKEN_HPP
#define KEYCARDACCESS_MEMBER_TOKEN_HPP

#include <desfire/tag.hpp>
#include "config.hpp"

namespace ka {

    using key_t = desfire::key<desfire::cipher_type::aes128>;

    class member_token {
        /**
         * @note Mutable because interacting with the tag requires non-const access.
         */
        mutable desfire::tag *_tag;

        [[nodiscard]] inline desfire::tag &tag() const;
    public:
        template <class... Tn>
        using r = desfire::tag::result<Tn...>;

        using id_t = std::array<std::uint8_t, 7>;

        inline explicit member_token(desfire::tag &tag);
        member_token(member_token const &) = delete;
        member_token(member_token &&) = default;
        member_token &operator=(member_token const &) = delete;
        member_token &operator=(member_token &&) = default;

        /**
         * @brief The ID of the token, as in @ref desfire::tag::get_card_uid().
         */
        [[nodiscard]] r<id_t> id() const;

        /**
         * @brief Computes the root key of the token.
         * Note that we do not use a pre-shared key for this, rather, we simply derive an
         * token-specific key to differentiate from @ref config::master_key. The user is free to
         * tamper with their token. In the worst case, they might delete the access application
         * and need a redeploy.
         * @see get_root_key(id_t, config const &)
         * @return A key which gives root access to the card.
         */
        [[nodiscard]] r<key_t> get_root_key(config const &cfg = system_config()) const;

        /**
         * @brief A differentiated root key to be used with this token.
         * This uses @ref desfire::kdf_an10922 to differentiate @ref config::master_key into a token-specific
         * root key. It uses the @p token_id and @ref config::differentiation_salt as differentiation input data.
         * @param token_id Id of the token
         * @param cfg Current configuration
         * @return A key.
         */
        [[nodiscard]] static key_t get_root_key(id_t token_id, config const &cfg = system_config());
    };

}

namespace ka {
    member_token::member_token(desfire::tag &tag) : _tag{&tag} {}

    desfire::tag &member_token::tag() const {
        return *_tag;
    }
}

#endif//KEYCARDACCESS_MEMBER_TOKEN_HPP
