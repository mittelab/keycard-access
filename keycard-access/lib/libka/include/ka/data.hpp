//
// Created by spak on 1/8/23.
//

#ifndef KEYCARD_ACCESS_DATA_HPP
#define KEYCARD_ACCESS_DATA_HPP

#include <cmath>
#include <desfire/data.hpp>
#include <desfire/keys.hpp>
#include <desfire/tag.hpp>
#include <ka/misc.hpp>
#include <neargye/semver.hpp>

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

    constexpr std::strong_ordering operator<=>(gate_id gid1, gate_id gid2);
    constexpr std::strong_ordering operator<=>(std::uint32_t gid1, gate_id gid2);
    constexpr std::strong_ordering operator<=>(gate_id gid1, std::uint32_t gid2);

    constexpr gate_id operator""_g(unsigned long long int id);

    template <class... Tn>
    using r = desfire::result<Tn...>;

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

    using hash_type = mlab::tagged_array<hash_tag, 64>;
    using token_id = mlab::tagged_array<token_id_tag, 7>;

    struct gate_base_key_tag {};

    struct gate_base_key : public mlab::tagged_array<gate_base_key_tag, 32> {
        [[nodiscard]] gate_token_key derive_token_key(token_id const &token_id, std::uint8_t key_no) const;
    };

    [[nodiscard]] constexpr std::uint64_t pack_token_id(token_id id);

    [[nodiscard]] token_id id_from_nfc_id(std::vector<std::uint8_t> const &d);

    [[nodiscard]] constexpr std::uint32_t pack_app_id(desfire::app_id aid);
    [[nodiscard]] constexpr desfire::app_id unpack_app_id(std::uint32_t aid);

    struct identity {
        token_id id;
        std::string holder;
        std::string publisher;

        [[nodiscard]] std::string string_representation() const;
        [[nodiscard]] hash_type hash() const;

        [[nodiscard]] bool operator==(identity const &other) const;
        [[nodiscard]] bool operator!=(identity const &other) const;
    };

    struct fw_info {
        semver::version semantic_version{0, 0, 0, semver::prerelease::alpha, 0};
        std::string commit_info{};
        std::string app_name{};
        std::string platform_code{};

        [[nodiscard]] static fw_info get_running_fw();

        /**
         * Returns a string that prefixes every version of this firmware, given by "app_name-platform"
         */
        [[nodiscard]] std::string get_fw_bin_prefix() const;

        /**
         * Returns true if and only if an OTA update has just occurred and the firmware was not verified yet.
         * @see
         *  - mark_running_fw_as_verified
         *  - rollback_running_fw
         */
        [[nodiscard]] static bool is_running_fw_pending_verification();

        /**
         * Marks this firmware as safe and prevents rollback on the next boot.
         */
        static void running_fw_mark_verified();

        /**
         * Triggers rollback of the previous fw.
         */
        static void running_fw_rollback();

        [[nodiscard]] std::string to_string() const;
    };

};// namespace ka

namespace mlab {
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

    constexpr std::uint64_t pack_token_id(token_id id) {
        std::uint64_t retval = 0;
        for (auto b : id) {
            retval = (retval << 8) | b;
        }
        return retval;
    }

    constexpr gate_id::gate_id(std::uint32_t idx) : _idx{idx} {}

    constexpr gate_id::operator std::uint32_t() const {
        return _idx;
    }

    constexpr gate_id operator""_g(unsigned long long int id) {
        constexpr unsigned long long int lo = std::numeric_limits<gate_id>::min();
        constexpr unsigned long long int hi = std::numeric_limits<gate_id>::max();
        return gate_id{std::uint32_t(std::clamp(id, lo, hi))};
    }

    constexpr std::strong_ordering operator<=>(gate_id gid1, gate_id gid2) {
        return std::uint32_t{gid1} <=> std::uint32_t{gid2};
    }
    constexpr std::strong_ordering operator<=>(std::uint32_t gid1, gate_id gid2) {
        return gid1 <=> std::uint32_t{gid2};
    }
    constexpr std::strong_ordering operator<=>(gate_id gid1, std::uint32_t gid2) {
        return std::uint32_t{gid1} <=> gid2;
    }

    constexpr std::pair<desfire::app_id, desfire::file_id> gate_id::app_and_file() const {
        return {unpack_app_id(aid_range_begin + _idx / gates_per_app), desfire::file_id(1 + _idx % gates_per_app)};
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
        const auto n_aid = pack_app_id(aid);
        return n_aid >= aid_range_begin and n_aid < aid_range_end;
    }

    constexpr bool gate_id::is_gate_app_and_file(desfire::app_id aid, desfire::file_id fid) {
        return is_gate_app(aid) and fid > 0 and fid <= gates_per_app;
    }

    constexpr std::pair<bool, gate_id> gate_id::from_app_and_file(desfire::app_id aid, desfire::file_id fid) {
        if (not is_gate_app_and_file(aid, fid)) {
            return {false, std::numeric_limits<gate_id>::max()};
        }
        const auto n_aid = pack_app_id(aid);
        return {true, gate_id{(n_aid - aid_range_begin) * gates_per_app + fid - 1}};
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

}// namespace ka
#endif//KEYCARD_ACCESS_DATA_HPP
