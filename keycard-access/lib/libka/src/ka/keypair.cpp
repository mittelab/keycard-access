//
// Created by spak on 10/5/22.
//

#include <cstring>
#include <esp_log.h>
#include <ka/keypair.hpp>
#include <sodium/crypto_scalarmult_curve25519.h>
#include <sodium/randombytes.h>

namespace ka {

    namespace serialize {
        static constexpr std::uint8_t pub_key_tag = 0x00;
        static constexpr std::uint8_t sec_key_tag = 0x01;
    }// namespace serialize

    pub_key::pub_key(raw_pub_key pub_key_raw) : _pk{pub_key_raw} {
    }

    pub_key::pub_key(mlab::range<std::uint8_t const *> pub_key_raw) : pub_key{} {
        if (pub_key_raw.size() != raw_pub_key::key_size) {
            ESP_LOGE("KA", "A raw public key has exactly a length of %d bytes.", raw_pub_key::key_size);
        } else {
            std::copy(std::begin(pub_key_raw), std::end(pub_key_raw), std::begin(_pk));
        }
    }

    sec_key::sec_key(raw_sec_key sec_key_raw) : _sk{sec_key_raw} {
    }

    sec_key::sec_key(mlab::range<std::uint8_t const *> sec_key_raw) : sec_key{} {
        if (sec_key_raw.size() != raw_sec_key::key_size) {
            ESP_LOGE("KA", "A raw public key has exactly a length of %d bytes.", raw_sec_key::key_size);
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

    key_pair::key_pair(raw_sec_key sec_key_raw) : sec_key{sec_key_raw}, pub_key{} {
        overwrite_pub_key();
    }

    key_pair::key_pair(sec_key sk) : sec_key{sk}, pub_key{} {
        overwrite_pub_key();
    }

    key_pair::key_pair(mlab::range<std::uint8_t const *> sec_key_raw) : sec_key{sec_key_raw}, pub_key{} {
        if (sec_key_raw.size() == raw_sec_key::key_size) {
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

    void key_pair::generate() {
        if (0 != crypto_box_keypair(_pk.data(), _sk.data())) {
            ESP_LOGE("KA", "Unable to generate a new keypair.");
            _pk = {};
            _sk = {};
        }
    }

    pub_key key_pair::drop_secret_key() const {
        return pub_key{raw_pk()};
    }

    bool key_pair::encrypt_for(pub_key const &recipient, mlab::bin_data &message) const {
        // Use the same buffer for everything. Store the message length
        const auto message_length = message.size();
        // Accommodate nonce and mac code
        message.resize(message.size() + crypto_box_curve25519xsalsa20poly1305_MACBYTES + crypto_box_curve25519xsalsa20poly1305_NONCEBYTES);
        auto message_view = message.data_view(0, message_length);
        auto ciphertext_view = message.data_view(0, message_length + crypto_box_curve25519xsalsa20poly1305_MACBYTES);
        auto nonce_view = message.data_view(ciphertext_view.size());
        // Generate nonce bytes
        randombytes_buf(nonce_view.data(), nonce_view.size());
        assert(nonce_view.size() == crypto_box_curve25519xsalsa20poly1305_NONCEBYTES);
        // Pipe into crypto_box_easy, overlap is allowed
        if (0 != crypto_box_easy(ciphertext_view.data(), message_view.data(), message_view.size(), nonce_view.data(),
                                 recipient.raw_pk().data(), raw_sk().data())) {
            ESP_LOGE("KA", "Unable to encrypt.");
            message.clear();
            return false;
        }
        return true;
    }

    bool key_pair::decrypt_from(pub_key const &sender, mlab::bin_data &ciphertext) const {
        if (ciphertext.size() < crypto_box_curve25519xsalsa20poly1305_MACBYTES + crypto_box_curve25519xsalsa20poly1305_NONCEBYTES) {
            ESP_LOGE("KA", "Invalid ciphertext, too short.");
            return false;
        }
        const auto message_length = ciphertext.size() - crypto_box_curve25519xsalsa20poly1305_MACBYTES - crypto_box_curve25519xsalsa20poly1305_NONCEBYTES;
        auto ciphertext_view = ciphertext.data_view(0, message_length + crypto_box_curve25519xsalsa20poly1305_MACBYTES);
        auto nonce_view = ciphertext.data_view(ciphertext_view.size());
        auto message_view = ciphertext.data_view(0, message_length);
        assert(nonce_view.size() == crypto_box_curve25519xsalsa20poly1305_NONCEBYTES);
        if (0 != crypto_box_open_easy(message_view.data(), ciphertext_view.data(), ciphertext_view.size(), nonce_view.data(),
                                      sender.raw_pk().data(), raw_sk().data())) {
            ESP_LOGE("KA", "Unable to decrypt.");
            ciphertext.clear();
            return false;
        }
        ciphertext.resize(message_length);
        return true;
    }

}// namespace ka
