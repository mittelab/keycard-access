//
// Created by spak on 1/8/23.
//

#include <ka/data.hpp>
#include <sodium/crypto_hash_sha512.h>

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
        std::string hex_string(mlab::range<std::uint8_t const *> rg) {
            std::string retval;
            retval.resize(2 * rg.size() + 1 /* final null separator */);
            auto bit = std::begin(rg);
            auto cit = std::begin(retval);
            for (; bit != std::end(rg); ++bit, cit += 2) {
                std::snprintf(&*cit, 3, "%02x", *bit);
            }
            return retval;
        }
    }

    std::string identity::string_representation() const {
        return util::hex_string(id) + "\n" + util::escape(holder) + "\n" + util::escape(publisher);
    }

    hash_type identity::hash() const {
        const std::string repr = string_representation();
        const mlab::bin_data data = mlab::bin_data::chain(
                mlab::prealloc(repr.size()),
                mlab::view_from_string(repr));
        hash_type h{};
        if (0 != crypto_hash_sha512(h.data(), data.data(), data.size())) {
            ESP_LOGE("KA", "Could not hash text and salt.");
            h = {};
        }
        return h;
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
