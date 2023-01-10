//
// Created by spak on 1/8/23.
//

#include <ka/data.hpp>

namespace ka {
    namespace util {
        std::string replace_all(std::string const &text, std::string const &search, std::string const &replace) {
            if (text.empty() or search.empty()) {
                return text;
            }
            std::string retval;
            retval.reserve(text.length());

            std::size_t last_pos = 0;
            std::size_t cur_pos = std::string::npos;

            auto append_cur_range = [&]() {
                const std::size_t beg = std::clamp(last_pos, 0u, text.length());
                const std::size_t end = std::clamp(cur_pos, beg, text.length());
                retval.append(
                        std::begin(text) + std::string::difference_type(beg),
                        std::begin(text) + std::string::difference_type(end)
                );
            };

            while ((cur_pos = text.find(search, last_pos)) != std::string::npos) {
                append_cur_range();
                retval.append(replace);
                last_pos = cur_pos + search.length();
            }
            append_cur_range();
            return retval;
        }
        std::string escape(std::string const &text) {
            return replace_all(replace_all(text, "\\", "\\\\"), "\n", "\\\n");
        }
    }

    std::string identity::concat() const {
        return util::escape(holder) + "\n" + util::escape(publisher);
    }

}

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