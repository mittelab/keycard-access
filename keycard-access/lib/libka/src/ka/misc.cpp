//
// Created by spak on 6/28/23.
//

#include <ka/misc.hpp>

namespace ka {
    [[nodiscard]] std::string concatenate(std::initializer_list<std::string_view> const &strs, std::string_view separator) {
        if (strs.size() == 0) {
            return "";
        }
        std::size_t tot_len = 0;
        for (auto const &s : strs) {
            tot_len += s.size();
        }
        std::string retval;
        retval.resize(tot_len + (strs.size() - 1) * separator.size(), '\0');
        auto jt = std::begin(strs);
        auto it = std::copy(std::begin(*jt), std::end(*jt), std::begin(retval));
        for (++jt; jt != std::end(strs); ++jt) {
            it = std::copy(std::begin(separator), std::end(separator), it);
            it = std::copy(std::begin(*jt), std::end(*jt), it);
        }
        return retval;
    }
}// namespace ka