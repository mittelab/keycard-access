//
// Created by spak on 6/28/23.
//

#ifndef KEYCARD_ACCESS_MISC_HPP
#define KEYCARD_ACCESS_MISC_HPP

#include <chrono>
#include <initializer_list>
#include <ka/data.hpp>
#include <string>

namespace ka {
    [[nodiscard]] std::string concatenate(std::initializer_list<std::string_view> const &strs, std::string_view separator = "");

    using datetime = std::chrono::time_point<std::chrono::system_clock>;

    /**
     * Parse C++ dates using C's strptime.
     */
    [[nodiscard]] std::optional<datetime> strptime(std::string_view s, std::string_view fmt);

    /**
     * Formats C++ dates using C's strftime.
     */
    [[nodiscard]] std::string strftime(datetime const &dt, std::string_view fmt);

    /**
     * Escapes backslashes and newlines (with a backslash in front).
     */
    [[nodiscard]] std::string escape(std::string const &text);

}// namespace ka

#endif//KEYCARD_ACCESS_MISC_HPP
