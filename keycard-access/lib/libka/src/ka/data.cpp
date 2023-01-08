//
// Created by spak on 1/8/23.
//

#include <ka/data.hpp>

namespace mlab {
    mlab::range<std::uint8_t const *> view_from_string(std::string const &s) {
        return mlab::range<std::uint8_t const *>{
                reinterpret_cast<std::uint8_t const *>(s.c_str()),
                reinterpret_cast<std::uint8_t const *>(s.c_str() + s.size())};
    }
    bin_data data_from_string(std::string const &s) {
        bin_data retval;
        retval << prealloc(s.size()) << view_from_string(s);
        return retval;
    }
    std::string data_to_string(bin_data const &bd) {
        const mlab::range<char const *> view{
                reinterpret_cast<char const *>(bd.data()),
                reinterpret_cast<char const *>(bd.data() + bd.size())};
        return std::string{std::begin(view), std::end(view)};
    }
}// namespace mlab
