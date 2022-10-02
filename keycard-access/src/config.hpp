//
// Created by spak on 10/2/22.
//

#ifndef KEYCARDACCESS_CONFIG_HPP
#define KEYCARDACCESS_CONFIG_HPP

#include <string>
#include <desfire/data.hpp>

namespace ka {

    using key_t = desfire::key<desfire::cipher_type::aes128>;

    struct config {
        key_t master_key;
        std::string differentiation_salt;
    };

    [[nodiscard]] config const &system_config();
}

#endif//KEYCARDACCESS_CONFIG_HPP
