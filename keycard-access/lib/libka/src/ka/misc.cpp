//
// Created by spak on 6/28/23.
//

#include <ka/misc.hpp>

namespace ka {
    [[nodiscard]] std::string concatenate(std::initializer_list<std::string_view> strs) {
        std::size_t tot_len = 0;
        for (auto const &s : strs) {
            tot_len += s.size();
        }
        std::string retval;
        retval.resize(tot_len);
        auto it = std::begin(retval);
        for (auto const &s : strs) {
            it = std::copy(std::begin(s), std::end(s), it);
        }
        return retval;
    }
}// namespace ka