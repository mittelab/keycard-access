//
// Created by spak on 1/8/23.
//

#ifndef KEYCARD_ACCESS_KEY_MANAGER_HPP
#define KEYCARD_ACCESS_KEY_MANAGER_HPP

#include <ka/data.hpp>

namespace ka {

    class one_key_to_bind_them {
    public:
        static constexpr std::size_t size = 32;
        static constexpr std::array<uint8_t, 16> pwhash_salt{KEYCARD_ACCESS_SALT};
        static constexpr unsigned long long pwhash_memlimit = 0x4000;
        static constexpr unsigned long long pwhash_opslimit = 2;

        constexpr one_key_to_bind_them() = default;
        explicit constexpr one_key_to_bind_them(std::array<std::uint8_t, 32> key);
        explicit one_key_to_bind_them(std::string const &password);

        [[nodiscard]] constexpr std::array<std::uint8_t, size> const &raw() const;

        /**
         * @brief A differentiated root key to be used as the root key of a token.
         * The user is free to know this and to tamper with the token, in the worst case it will delete the application.
         * @param token_id Id of the token
         * @return A key_type which gives root access to the card.
         */
        [[nodiscard]] token_root_key derive_token_root_key(token_id const &id) const;
        [[nodiscard]] gate_app_master_key derive_gate_app_master_key(token_id const &id, gate_id gid) const;
    private:
        std::array<std::uint8_t, size> _raw = {};
    };

}

namespace ka {
    constexpr std::array<std::uint8_t, one_key_to_bind_them::size> const &one_key_to_bind_them::raw() const {
        return _raw;
    }

    constexpr one_key_to_bind_them::one_key_to_bind_them(std::array<std::uint8_t, 32> key) : _raw{key} {}
}

#endif//KEYCARD_ACCESS_KEY_MANAGER_HPP
