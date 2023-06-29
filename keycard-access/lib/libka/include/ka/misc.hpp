//
// Created by spak on 6/28/23.
//

#ifndef KEYCARD_ACCESS_MISC_HPP
#define KEYCARD_ACCESS_MISC_HPP

#include <initializer_list>
#include <string>

namespace ka {
    [[nodiscard]] std::string concatenate(std::initializer_list<std::string_view> const &strs, std::string_view separator = "");

}// namespace ka

#endif//KEYCARD_ACCESS_MISC_HPP
