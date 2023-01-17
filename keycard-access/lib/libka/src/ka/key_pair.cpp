//
// Created by spak on 10/5/22.
//

#include <cstring>
#include <esp_log.h>
#include <ka/key_pair.hpp>
#include <sodium/crypto_box.h>
#include <sodium/crypto_kdf_blake2b.h>
#include <sodium/crypto_pwhash_argon2id.h>
#include <sodium/crypto_scalarmult_curve25519.h>
#include <sodium/randombytes.h>

#ifndef KEYCARD_ACCESS_SALT
#define KEYCARD_ACCESS_SALT "Mlab Super Hash"
#endif

namespace ka {
    namespace {
        constexpr std::array<char, crypto_kdf_blake2b_CONTEXTBYTES> root_key_context{"rootkey"};
        constexpr unsigned long long pwhash_memlimit = 0x2000;
        constexpr unsigned long long pwhash_opslimit = 4;
        constexpr std::array<uint8_t, 16> pwhash_salt{KEYCARD_ACCESS_SALT};

        template <class> struct size_of_array {};
        template <std::size_t N> struct  size_of_array<std::array<char, N>> {
            static constexpr std::size_t size = N;
        };
        template <std::size_t N> struct  size_of_array<std::array<std::uint8_t, N>> {
            static constexpr std::size_t size = N;
        };
    }

    static_assert(raw_pub_key::array_size == crypto_box_PUBLICKEYBYTES);
    static_assert(raw_sec_key::array_size == crypto_box_SECRETKEYBYTES);
    static_assert(raw_sec_key::array_size == crypto_kdf_blake2b_KEYBYTES);
    static_assert(pwhash_salt.size() == crypto_pwhash_argon2id_SALTBYTES);
    static_assert(pwhash_memlimit >= crypto_pwhash_argon2id_MEMLIMIT_MIN and pwhash_memlimit <= crypto_pwhash_argon2id_MEMLIMIT_MAX);
    static_assert(pwhash_opslimit >= crypto_pwhash_argon2id_OPSLIMIT_MIN and pwhash_opslimit <= crypto_pwhash_argon2id_OPSLIMIT_MAX);


    pub_key::pub_key(raw_pub_key pub_key_raw) : _pk{pub_key_raw} {
    }

    pub_key::pub_key(mlab::range<std::uint8_t const *> pub_key_raw) : pub_key{} {
        if (pub_key_raw.size() != raw_pub_key::array_size) {
            ESP_LOGE("KA", "A raw public key has exactly a length of %d bytes.", raw_pub_key::array_size);
        } else {
            std::copy(std::begin(pub_key_raw), std::end(pub_key_raw), std::begin(_pk));
        }
    }

    sec_key::sec_key(raw_sec_key sec_key_raw) : _sk{sec_key_raw} {
    }

    sec_key::sec_key(mlab::range<std::uint8_t const *> sec_key_raw) : sec_key{} {
        if (sec_key_raw.size() != raw_sec_key::array_size) {
            ESP_LOGE("KA", "A raw public key has exactly a length of %d bytes.", raw_sec_key::array_size);
        } else {
            std::copy(std::begin(sec_key_raw), std::end(sec_key_raw), std::begin(_sk));
        }
    }

    raw_pub_key const &pub_key::raw_pk() const {
        return _pk;
    }

    raw_sec_key const &sec_key::raw_sk() const {
        return _sk;
    }

    token_root_key sec_key::derive_token_root_key(token_id const &id) const {
        std::array<std::uint8_t, key_type::size> derived_key_data{};
        if (0 != crypto_kdf_blake2b_derive_from_key(
                         derived_key_data.data(), derived_key_data.size(),
                         pack_token_id(id),
                         root_key_context.data(),
                         raw_sk().data())) {
            ESP_LOGE("KA", "Unable to derive root key.");
        }
        return token_root_key{0, derived_key_data};
    }

    key_pair::key_pair(raw_sec_key sec_key_raw) : sec_key{sec_key_raw}, pub_key{} {
        overwrite_pub_key();
    }

    key_pair::key_pair(randomize_t) : key_pair{} {
        generate_random();
    }

    key_pair::key_pair(sec_key sk) : sec_key{sk}, pub_key{} {
        overwrite_pub_key();
    }

    key_pair::key_pair(mlab::range<std::uint8_t const *> sec_key_raw) : sec_key{sec_key_raw}, pub_key{} {
        if (sec_key_raw.size() == raw_sec_key::array_size) {
            overwrite_pub_key();
        }
    }


    void key_pair::overwrite_pub_key() {
        if (auto [pub_key_raw, success] = derive_pub_key(); success) {
            _pk = pub_key_raw;
        } else {
            _pk = {};
            _sk = {};
        }
    }

    std::pair<raw_pub_key, bool> sec_key::derive_pub_key() const {
        raw_pub_key retval{};
        if (crypto_scalarmult_curve25519_base(retval.data(), _sk.data()) != 0) {
            ESP_LOGE("KA", "Could not derive public key from secret key.");
            return {{}, false};
        }
        return {retval, true};
    }

    bool key_pair::is_valid() const {
        if (const auto [pub_key_raw, success] = derive_pub_key(); success) {
            return raw_pk() == pub_key_raw;
        }
        return false;
    }

    void key_pair::generate_random() {
        if (0 != crypto_box_keypair(_pk.data(), _sk.data())) {
            ESP_LOGE("KA", "Unable to generate_random a new keypair.");
            _pk = {};
            _sk = {};
        }
    }

    void key_pair::generate_from_pwhash(std::string const &password) {
        static_assert(CONFIG_MAIN_TASK_STACK_SIZE > pwhash_memlimit, "libSodium operates on the stack, please increase the minimum stack size.");
        if (password.length() < crypto_pwhash_argon2id_PASSWD_MIN or
            password.length() > crypto_pwhash_argon2id_PASSWD_MAX)
        {
            ESP_LOGE("KA", "Password must be between %u and %u characters long.",
                     crypto_pwhash_argon2id_PASSWD_MIN,
                     crypto_pwhash_argon2id_PASSWD_MAX);
            return;
        }
        if (0 != crypto_pwhash_argon2id(
                         _sk.data(), _sk.size(),
                         password.data(), password.length(),
                         pwhash_salt.data(),
                         pwhash_opslimit, pwhash_memlimit,
                         crypto_pwhash_argon2id_ALG_ARGON2ID13))
        {
            ESP_LOGE("KA", "Unable to derive key from password, out of memory.");
            _pk = {};
            _sk = {};
        } else {
            // Derive public key
            if (const auto [pub_key_raw, success] = derive_pub_key(); success) {
                _pk = pub_key_raw;
            } else {
                ESP_LOGE("KA", "Unable to derive a public key from the secret key.");
                _pk = {};
                _sk = {};
            }
        }
    }

    pub_key key_pair::drop_secret_key() const {
        return pub_key{raw_pk()};
    }

    bool key_pair::encrypt_for(pub_key const &recipient, mlab::bin_data &message) const {
        // Use the same buffer for everything. Store the message length
        const auto message_length = message.size();
        // Accommodate nonce and mac code
        message.resize(message.size() + crypto_box_MACBYTES + crypto_box_NONCEBYTES);
        auto message_view = message.data_view(0, message_length);
        auto ciphertext_view = message.data_view(0, message_length + crypto_box_MACBYTES);
        auto nonce_view = message.data_view(ciphertext_view.size());
        // Generate nonce bytes
        randombytes_buf(nonce_view.data(), nonce_view.size());
        assert(nonce_view.size() == crypto_box_curve25519xsalsa20poly1305_NONCEBYTES);
        // Pipe into crypto_box_easy, overlap is allowed
        if (0 != crypto_box_easy(
                         ciphertext_view.data(), message_view.data(),
                         message_view.size(), nonce_view.data(),
                         recipient.raw_pk().data(), raw_sk().data())) {
            ESP_LOGE("KA", "Unable to encrypt.");
            message.clear();
            return false;
        }
        return true;
    }

    bool key_pair::decrypt_from(pub_key const &sender, mlab::bin_data &ciphertext) const {
        if (ciphertext.size() < crypto_box_MACBYTES + crypto_box_NONCEBYTES) {
            ESP_LOGE("KA", "Invalid ciphertext, too short.");
            return false;
        }
        const auto message_length = ciphertext.size() - crypto_box_MACBYTES - crypto_box_NONCEBYTES;
        auto ciphertext_view = ciphertext.data_view(0, message_length + crypto_box_MACBYTES);
        auto nonce_view = ciphertext.data_view(ciphertext_view.size());
        auto message_view = ciphertext.data_view(0, message_length);
        assert(nonce_view.size() == crypto_box_NONCEBYTES);
        if (0 != crypto_box_open_easy(
                         message_view.data(), ciphertext_view.data(),
                         ciphertext_view.size(), nonce_view.data(),
                         sender.raw_pk().data(), raw_sk().data())) {
            ESP_LOGE("KA", "Unable to decrypt.");
            ciphertext.clear();
            return false;
        }
        ciphertext.resize(message_length);
        return true;
    }

}// namespace ka
