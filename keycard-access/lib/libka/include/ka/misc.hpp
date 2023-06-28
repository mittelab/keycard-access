//
// Created by spak on 6/28/23.
//

#ifndef KEYCARD_ACCESS_MISC_HPP
#define KEYCARD_ACCESS_MISC_HPP

#include <string>
#include <vector>

namespace ka {
    [[nodiscard]] std::string concatenate_views(std::vector<std::string_view> const &strs, std::string_view separator = "");

    [[nodiscard]] std::string concatenate_strings(std::vector<std::string> const &strs, std::string_view separator = "");

}// namespace ka

#endif//KEYCARD_ACCESS_MISC_HPP
