//
// Created by spak on 1/8/23.
//

#ifndef KEYCARD_ACCESS_DATA_HPP
#define KEYCARD_ACCESS_DATA_HPP

#include <cmath>
#include <desfire/data.hpp>
#include <desfire/keys.hpp>
#include <desfire/tag.hpp>

namespace ka {

    using key_type = desfire::key<desfire::cipher_type::aes128>;

    class gate_id {
        std::uint32_t _idx = 0;

    public:
        using value_type = std::uint32_t;

        /**
         * @addtogroup Conversion between Gate ID and Desfire App
         * According to AN10787 §3.10 describing the Mifare application directory, on Desfire cards
         * we lock the first nibble of the app id to `F`, then we apply the functional cluster code as
         * per ANNEX C, which in case of access control is `0x51---0x54`. The remaining nibbles are free.
         * Thus we obtain 0x3fff possible gates (which we will never reach because of memory, but ok).
         * @{
         */
        static constexpr std::uint32_t aid_range_begin = 0xf51000;
        static constexpr std::uint32_t aid_range_end = 0xf55000;
        static constexpr std::uint32_t gates_per_app = 13;
        /**
         * @}
         */

        static constexpr desfire::app_id first_aid = {0xf5, 0x10, 0x00};

        constexpr gate_id() = default;
        explicit constexpr gate_id(std::uint32_t idx);

        constexpr operator std::uint32_t() const;

        [[nodiscard]] constexpr std::pair<desfire::app_id, desfire::file_id> app_and_file() const;
        [[nodiscard]] constexpr desfire::app_id app() const;
        [[nodiscard]] constexpr desfire::file_id file() const;
        [[nodiscard]] constexpr std::uint8_t key_no() const;

        [[nodiscard]] static constexpr bool is_gate_app(desfire::app_id aid);
        [[nodiscard]] static constexpr bool is_gate_app_and_file(desfire::app_id aid, desfire::file_id fid);
        [[nodiscard]] static constexpr std::pair<bool, gate_id> from_app_and_file(desfire::app_id aid, desfire::file_id fid);
    };

    constexpr gate_id operator""_g(unsigned long long int id);

    template <class, std::size_t Size>
    struct tagged_array : public std::array<std::uint8_t, Size> {
        static constexpr std::size_t array_size = Size;

        [[nodiscard]] bool operator==(tagged_array const &other) const;
        [[nodiscard]] bool operator!=(tagged_array const &other) const;
    };

    template <class... Tn>
    using r = desfire::tag::result<Tn...>;

    struct derived_key {};

    struct gate_token_key : public key_type, public derived_key {
        using key_type::key_type;
    };

    struct token_root_key : public key_type, public derived_key {
        using key_type::key_type;
    };

    struct gate_app_master_key : public gate_token_key {
        using gate_token_key::gate_token_key;
    };

    struct hash_tag;
    struct token_id_tag;

    using hash_type = tagged_array<hash_tag, 64>;
    using token_id = tagged_array<token_id_tag, 7>;

    struct identity {
        token_id id;
        std::string holder;
        std::string publisher;

        [[nodiscard]] std::string string_representation() const;
        [[nodiscard]] hash_type hash() const;

        [[nodiscard]] bool operator==(identity const &other) const;
        [[nodiscard]] bool operator!=(identity const &other) const;
    };

    namespace util {
        [[nodiscard]] std::string replace_all(std::string const &text, std::string const &search, std::string const &replace);
        /**
         * Escapes backslashes and newlines (with a backslash in front).
         */
        [[nodiscard]] std::string escape(std::string const &text);

        [[nodiscard]] constexpr std::uint64_t pack_token_id(token_id id);

        [[nodiscard]] std::string hex_string(mlab::range<std::uint8_t const *> rg);
        [[nodiscard]] std::string hex_string(std::vector<std::uint8_t> const &v);

        template <std::size_t N>
        [[nodiscard]] std::string hex_string(std::array<std::uint8_t, N> const &a);

        [[nodiscard]] token_id id_from_nfc_id(std::vector<std::uint8_t> const &d);

        [[nodiscard]] constexpr std::uint32_t pack_app_id(desfire::app_id aid);
        [[nodiscard]] constexpr desfire::app_id unpack_app_id(std::uint32_t aid);
    }// namespace util

};// namespace ka

namespace mlab {
    [[nodiscard]] mlab::range<std::uint8_t const *> view_from_string(std::string const &s);
    [[nodiscard]] bin_data data_from_string(std::string const &s);
    [[nodiscard]] std::string data_to_string(bin_data const &bd);
    [[nodiscard]] std::string data_to_string(mlab::range<mlab::bin_data::const_iterator> rg);
    [[nodiscard]] std::string data_to_string(mlab::range<std::uint8_t const *> rg);

    bin_stream &operator>>(bin_stream &s, ka::identity &id);
    bin_data &operator<<(bin_data &bd, ka::identity const &id);
}// namespace mlab

namespace std {
    template <>
    struct numeric_limits<ka::gate_id> {
        static constexpr bool is_specialized = true;
        static constexpr bool is_signed = false;
        static constexpr bool is_integer = true;
        static constexpr bool is_exact = true;
        static constexpr bool has_infinity = false;
        static constexpr bool has_quiet_NaN = false;
        static constexpr bool has_signaling_NaN = false;
        static constexpr bool has_denorm = false;
        static constexpr bool has_denorm_loss = false;
        static constexpr float_round_style round_style = std::round_toward_zero;
        static constexpr bool is_iec559 = false;
        static constexpr bool is_bounded = true;
        static constexpr bool is_modulo = false;
        static constexpr int digits = 8 * sizeof(std::uint32_t);
        static constexpr int digits10 = 9;
        static constexpr int max_digits10 = 0;
        static constexpr int radix = 2;
        static constexpr int min_exponent = 0;
        static constexpr int min_exponent10 = 0;
        static constexpr int max_exponent = 0;
        static constexpr int max_exponent10 = 0;
        static constexpr bool traps = true;
        static constexpr bool tinyness_before = false;

        static constexpr ka::gate_id min() noexcept { return ka::gate_id{0}; }
        static constexpr ka::gate_id lowest() noexcept { return ka::gate_id{0}; }
        static constexpr ka::gate_id max() noexcept {
            return ka::gate_id{(ka::gate_id::aid_range_end - ka::gate_id::aid_range_begin) * ka::gate_id::gates_per_app + 1};
        }
        static constexpr ka::gate_id epsilon() noexcept { return ka::gate_id{0}; }
        static constexpr ka::gate_id round_error() noexcept { return ka::gate_id{0}; }
        static constexpr ka::gate_id infinity() noexcept { return ka::gate_id{0}; }
        static constexpr ka::gate_id quiet_NaN() noexcept { return ka::gate_id{0}; }
        static constexpr ka::gate_id signaling_NaN() noexcept { return ka::gate_id{0}; }
        static constexpr ka::gate_id denorm_min() noexcept { return ka::gate_id{0}; }
    };
}// namespace std

namespace ka {

    constexpr gate_id::gate_id(std::uint32_t idx) : _idx{idx} {}

    constexpr gate_id::operator std::uint32_t() const {
        return _idx;
    }

    constexpr gate_id operator""_g(unsigned long long int id) {
        constexpr unsigned long long int lo = std::numeric_limits<gate_id>::min();
        constexpr unsigned long long int hi = std::numeric_limits<gate_id>::min();
        return gate_id{std::uint32_t(std::clamp(id, lo, hi))};
    }

    constexpr std::pair<desfire::app_id, desfire::file_id> gate_id::app_and_file() const {
        return {util::unpack_app_id(aid_range_begin + _idx / gates_per_app), desfire::file_id(1 + _idx % gates_per_app)};
    }

    constexpr desfire::app_id gate_id::app() const {
        return app_and_file().first;
    }

    constexpr desfire::file_id gate_id::file() const {
        return app_and_file().second;
    }

    constexpr std::uint8_t gate_id::key_no() const {
        return file();
    }

    constexpr bool gate_id::is_gate_app(desfire::app_id aid) {
        const auto n_aid = util::pack_app_id(aid);
        return n_aid >= aid_range_begin and n_aid < aid_range_end;
    }

    constexpr bool gate_id::is_gate_app_and_file(desfire::app_id aid, desfire::file_id fid) {
        return is_gate_app(aid) and fid > 0 and fid <= gates_per_app;
    }

    constexpr std::pair<bool, gate_id> gate_id::from_app_and_file(desfire::app_id aid, desfire::file_id fid) {
        if (not is_gate_app_and_file(aid, fid)) {
            return {false, std::numeric_limits<gate_id>::max()};
        }
        const auto n_aid = util::pack_app_id(aid);
        return {true, gate_id{(n_aid - aid_range_begin) * gates_per_app + fid - 1}};
    }

    template <class T, std::size_t Size>
    bool tagged_array<T, Size>::operator==(tagged_array const &other) const {
        return std::equal(std::begin(*this), std::end(*this), std::begin(other));
    }

    template <class T, std::size_t Size>
    bool tagged_array<T, Size>::operator!=(tagged_array const &other) const {
        return not operator==(other);
    }


    namespace util {

        constexpr std::uint64_t pack_token_id(token_id id) {
            std::uint64_t retval = 0;
            for (auto b : id) {
                retval = (retval << 8) | b;
            }
            return retval;
        }

        constexpr std::uint32_t pack_app_id(desfire::app_id aid) {
            return (std::uint32_t(aid[0]) << 16) |
                   (std::uint32_t(aid[1]) << 8) |
                   std::uint32_t(aid[2]);
        }
        constexpr desfire::app_id unpack_app_id(std::uint32_t aid) {
            return {std::uint8_t((aid >> 16) & 0xff),
                    std::uint8_t((aid >> 8) & 0xff),
                    std::uint8_t(aid & 0xff)};
        }
        template <std::size_t N>
        std::string hex_string(std::array<std::uint8_t, N> const &a) {
            return hex_string(mlab::make_range<std::uint8_t const *>(a.data(), a.data() + a.size()));
        }
    }// namespace util

}// namespace ka
#endif//KEYCARD_ACCESS_DATA_HPP
