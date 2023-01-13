//
// Created by spak on 1/8/23.
//

#ifndef KEYCARD_ACCESS_DATA_HPP
#define KEYCARD_ACCESS_DATA_HPP

#include <desfire/data.hpp>
#include <desfire/keys.hpp>
#include <desfire/tag.hpp>

namespace ka {

    using key_type = desfire::key<desfire::cipher_type::aes128>;
    using std_file_settings = desfire::file_settings<desfire::file_type::standard>;

    using token_id = std::array<std::uint8_t, 7>;
    using gate_id = std::uint32_t;

    template <class, std::size_t Size>
    struct tagged_array : public std::array<std::uint8_t, Size> {
        static constexpr std::size_t key_size = Size;

        [[nodiscard]] bool operator==(tagged_array const &other) const;
        [[nodiscard]] bool operator!=(tagged_array const &other) const;
    };

    template <class... Tn>
    using r = desfire::tag::result<Tn...>;

    struct derived_key {};

    struct app_master_key : public key_type {
        using key_type::key_type;
    };

    struct gate_app_master_key : public app_master_key, public derived_key {
        using app_master_key::app_master_key;
    };

    struct token_root_key : public key_type, public derived_key {
        using key_type::key_type;
    };

    using ticket_salt = std::array<std::uint8_t, 32>;
    using gate_context_data = std::array<char, 8>;

    struct hash_tag;

    using hash_type = tagged_array<hash_tag, 64>;

    struct identity {
        token_id id;
        std::string holder;
        std::string publisher;

        [[nodiscard]] std::string string_representation() const;
        [[nodiscard]] hash_type hash() const;
    };

    enum struct gate_status : std::uint8_t {
        unknown = 0b00,
        enrolled = 0b01,
        auth_ready = 0b10,
        broken = enrolled | auth_ready
    };

    [[nodiscard]] inline bool operator&(gate_status gs1, gate_status gs2);
    [[nodiscard]] inline gate_status operator|(gate_status gs1, gate_status gs2);

    namespace util {
        [[nodiscard]] std::string replace_all(std::string const &text, std::string const &search, std::string const &replace);
        /**
         * Escapes backslashes and newlines (with a backslash in front).
         */
        [[nodiscard]] std::string escape(std::string const &text);

        [[nodiscard]] constexpr std::uint64_t pack_token_id(token_id id);

        [[nodiscard]] std::string hex_string(mlab::range<std::uint8_t const *> rg);

        template <std::size_t N>
        [[nodiscard]] std::string hex_string(std::array<std::uint8_t, N> const &a);
    }

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

    template <class T, std::size_t Size>
    bool tagged_array<T, Size>::operator==(tagged_array const &other) const {
        return std::equal(std::begin(*this), std::end(*this), std::begin(other));
    }

    template <class T, std::size_t Size>
    bool tagged_array<T, Size>::operator!=(tagged_array const &other) const {
        return not operator==(other);
    }

    constexpr std::uint64_t pack_token_id(token_id id) {
        std::uint64_t retval = 0;
        for (auto b : id) {
            retval = (retval << 8) | b;
        }
        return retval;
    }

    namespace util {

        template <std::size_t N>
        std::string hex_string(std::array<std::uint8_t, N> const &a) {
            return hex_string(mlab::make_range<std::uint8_t const *>(a.data(), a.data() + a.size()));
        }
    }

}// namespace ka
#endif//KEYCARD_ACCESS_DATA_HPP
