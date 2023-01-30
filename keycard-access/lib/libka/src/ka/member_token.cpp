//
// Created by spak on 9/29/22.
//

#include <desfire/esp32/utils.hpp>
#include <desfire/kdf.hpp>
#include <ka/desfire_fs.hpp>
#include <ka/gate.hpp>
#include <ka/member_token.hpp>
#include <sodium/randombytes.h>

namespace ka {

    member_token::member_token(desfire::tag &tag) : _tag{&tag} {}

    pn532::post_interaction member_token_responder::interact_with_tag(desfire::tag &tag) {
        member_token token{tag};
        return interact_with_token(token);
    }


}// namespace ka