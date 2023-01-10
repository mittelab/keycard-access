//
// Created by spak on 1/8/23.
//

#include <ka/key_manager.hpp>
#include <sodium/crypto_kdf_blake2b.h>
#include <sodium/crypto_pwhash_argon2id.h>

namespace ka {
    namespace {
        constexpr std::array<char, crypto_kdf_blake2b_CONTEXTBYTES> root_key_context{"rootkey"};
        static_assert(one_key_to_bind_them::size == crypto_kdf_blake2b_KEYBYTES);
    }

    token_root_key one_key_to_bind_them::derive_token_root_key(token_id const &id) const {
        std::array<std::uint8_t, key_type::size> derived_key_data{};
        if (0 != crypto_kdf_blake2b_derive_from_key(
                         derived_key_data.data(), derived_key_data.size(),
                         pack_token_id(id),
                         root_key_context.data(),
                         raw().data())) {
            ESP_LOGE("KA", "Unable to derive root key.");
        }
        return token_root_key{0, derived_key_data};
    }

    gate_app_shared_key one_key_to_bind_them::derive_gate_app_master_key(token_id const &id, gate_id gid) const {
        std::array<std::uint8_t, key_type::size> derived_key_data{};
        const std::array<char, crypto_kdf_blake2b_CONTEXTBYTES> gate_key_context{
                'g', 'a', 't', 'e',
                char(gid & 0xff),
                char((gid >> 8) & 0xff),
                char((gid >> 16) & 0xff),
                char((gid >> 24) & 0xff)};

        if (0 != crypto_kdf_blake2b_derive_from_key(
                         derived_key_data.data(), derived_key_data.size(),
                         pack_token_id(id),
                         gate_key_context.data(),
                         raw().data())) {
            ESP_LOGE("KA", "Unable to derive gate key.");
        }
        return gate_app_shared_key{0, derived_key_data};
    }

    one_key_to_bind_them::one_key_to_bind_them(const std::string &password) : one_key_to_bind_them{} {
        static_assert(pwhash_salt.size() == crypto_pwhash_argon2id_SALTBYTES);
        static_assert(pwhash_memlimit >= crypto_pwhash_argon2id_MEMLIMIT_MIN and pwhash_memlimit <= crypto_pwhash_argon2id_MEMLIMIT_MAX);
        static_assert(pwhash_opslimit >= crypto_pwhash_argon2id_OPSLIMIT_MIN and pwhash_opslimit <= crypto_pwhash_argon2id_OPSLIMIT_MAX);

        if (password.length() < crypto_pwhash_argon2id_PASSWD_MIN or
            password.length() > crypto_pwhash_argon2id_PASSWD_MAX)
        {
            ESP_LOGE("KA", "Password must be between %u and %u characters long.",
                     crypto_pwhash_argon2id_PASSWD_MIN,
                     crypto_pwhash_argon2id_PASSWD_MAX);
            return;
        }
        if (0 != crypto_pwhash_argon2id(
                         _raw.data(), _raw.size(),
                         password.data(), password.length(),
                         pwhash_salt.data(),
                         pwhash_opslimit, pwhash_memlimit,
                         crypto_pwhash_argon2id_ALG_ARGON2ID13))
        {
            ESP_LOGE("KA", "Unable to derive key from password, out of memory.");
        }
    }
}// namespace ka::key