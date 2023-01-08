//
// Created by spak on 10/2/22.
//

#ifndef KEYCARDACCESS_CONFIG_HPP
#define KEYCARDACCESS_CONFIG_HPP

#include <ka/data.hpp>
#include <string>

namespace ka {

    struct config {
        key_type master_key;
        std::string differentiation_salt;
    };

    [[nodiscard]] config const &system_config();
}// namespace ka

#endif//KEYCARDACCESS_CONFIG_HPP
