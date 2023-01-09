//
// Created by spak on 1/8/23.
//

#ifndef KEYCARD_ACCESS_DATA_HPP
#define KEYCARD_ACCESS_DATA_HPP

#include <desfire/data.hpp>
#include <desfire/keys.hpp>
#include <desfire/tag.hpp>
#include <ka/config.hpp>

namespace ka {

    using key_type = desfire::key<desfire::cipher_type::aes128>;
    using std_file_settings = desfire::file_settings<desfire::file_type::standard>;

    using token_id = std::array<std::uint8_t, 7>;
    using gate_id = std::uint32_t;

    template <class... Tn>
    using r = desfire::tag::result<Tn...>;

    namespace util {
        [[nodiscard]] std::string replace_all(std::string const &text, std::string const &search, std::string const &replace);
        /**
         * Escapes backslashes and newlines (with a backslash in front).
         */
        [[nodiscard]] std::string escape(std::string const &text);

        [[nodiscard]] constexpr std::uint64_t pack_token_id(token_id id);
    }

    struct identity {
        std::string holder;
        std::string publisher;

        [[nodiscard]] std::string concat() const;
    };

    enum struct gate_status : std::uint8_t {
        unknown = 0b00,
        enrolled = 0b01,
        auth_ready = 0b10,
        broken = enrolled | auth_ready
    };

    [[nodiscard]] inline bool operator&(gate_status gs1, gate_status gs2);
    [[nodiscard]] inline gate_status operator|(gate_status gs1, gate_status gs2);

}// namespace ka

namespace mlab {
    [[nodiscard]] mlab::range<std::uint8_t const *> view_from_string(std::string const &s);
    [[nodiscard]] bin_data data_from_string(std::string const &s);
    [[nodiscard]] std::string data_to_string(bin_data const &bd);
}// namespace mlab

namespace ka {

    bool operator&(gate_status gs1, gate_status gs2) {
        using numeric_t = std::underlying_type_t<gate_status>;
        return (static_cast<numeric_t>(gs1) & static_cast<numeric_t>(gs2)) != 0;
    }

    gate_status operator|(gate_status gs1, gate_status gs2) {
        using numeric_t = std::underlying_type_t<gate_status>;
        return static_cast<gate_status>(static_cast<numeric_t>(gs1) | static_cast<numeric_t>(gs2));
    }

    constexpr std::uint64_t pack_token_id(token_id id) {
        std::uint64_t retval = 0;
        for (auto b : id) {
            retval = (retval << 8) | b;
        }
        return retval;
    }


}// namespace ka
#endif//KEYCARD_ACCESS_DATA_HPP
