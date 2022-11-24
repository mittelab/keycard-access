//
// Created by spak on 10/2/22.
//

#ifndef KEYCARDACCESS_CONFIG_HPP
#define KEYCARDACCESS_CONFIG_HPP

#include <desfire/keys.hpp>
#include <string>

namespace ka {

    using tag_key = desfire::key<desfire::cipher_type::aes128>;

    struct config {
        tag_key master_key;
        std::string differentiation_salt;
    };

    [[nodiscard]] config const &system_config();
}// namespace ka

#endif//KEYCARDACCESS_CONFIG_HPP
