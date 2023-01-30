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

    public:
        explicit member_token(desfire::tag &tag);

        [[nodiscard]] inline desfire::tag &tag() const;
    };

}// namespace ka

namespace ka {

    desfire::tag &member_token::tag() const {
        return *_tag;
    }

}// namespace ka

#endif//KEYCARDACCESS_MEMBER_TOKEN_HPP
