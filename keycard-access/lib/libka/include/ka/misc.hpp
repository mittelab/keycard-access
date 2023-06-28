//
// Created by spak on 6/28/23.
//

#ifndef KEYCARD_ACCESS_MISC_HPP
#define KEYCARD_ACCESS_MISC_HPP

#include <string>
#include <initializer_list>

namespace ka {
    [[nodiscard]] std::string concatenate(std::initializer_list<std::string_view> strs);
}

#endif//KEYCARD_ACCESS_MISC_HPP
