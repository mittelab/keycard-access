//
// Created by spak on 6/28/23.
//

#include <mlab/strutils.hpp>
#include <ka/misc.hpp>

namespace ka {

    std::optional<datetime> strptime(std::string_view s, std::string_view fmt) {
        if (std::tm tm{}; ::strptime(s.data(), fmt.data(), &tm) != nullptr) {
            const auto c_time = std::mktime(&tm);
            return std::chrono::system_clock::from_time_t(c_time);
        }
        return std::nullopt;
    }

    std::string strftime(datetime const &dt, std::string_view fmt) {
        std::array<char, 64> buffer{};
        const auto c_time = std::chrono::system_clock::to_time_t(dt);
        const auto *tm = std::localtime(&c_time);
        if (const auto nchars = std::strftime(buffer.data(), buffer.size(), fmt.data(), tm); nchars > 0) {
            return {std::begin(buffer), std::begin(buffer) + nchars};
        }
        return "<date format too long>";
    }

    std::string escape(std::string const &text) {
        return mlab::replace_all(mlab::replace_all(text, "\\", "\\\\"), "\n", "\\\n");
    }

}// namespace ka