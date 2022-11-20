//
// Created by spak on 10/5/22.
//

#ifndef KEYCARDACCESS_KEYPAIR_HPP
#define KEYCARDACCESS_KEYPAIR_HPP

#include <array>
#include <mlab/bin_data.hpp>
#include <sodium/crypto_box.h>
#include <sodium/crypto_sign.h>

namespace ka {
    template <class T, std::size_t Size>
    struct tagged_array : public std::array<std::uint8_t, Size> {
        static constexpr std::size_t key_size = Size;
        using std::array<std::uint8_t, Size>::array;

        [[nodiscard]] bool operator==(tagged_array const &other) const;
        [[nodiscard]] bool operator!=(tagged_array const &other) const;
    };

    struct pub_key_tag {};
    struct sec_key_tag {};

    using raw_pub_key = tagged_array<pub_key_tag, crypto_sign_ed25519_PUBLICKEYBYTES>;
    using raw_sec_key = tagged_array<sec_key_tag, crypto_sign_ed25519_SECRETKEYBYTES>;


    class pub_key {
    public:
        pub_key() = default;
        explicit pub_key(raw_pub_key pub_key_raw);
        explicit pub_key(mlab::range<std::uint8_t const *> pub_key_raw);

        [[nodiscard]] raw_pub_key const &raw_pk() const;
    protected:
        raw_pub_key _pk{};
    };

    class sec_key {
    public:
        sec_key() = default;
        explicit sec_key(raw_sec_key sec_key_raw);
        explicit sec_key(mlab::range<std::uint8_t const *> sec_key_raw);

        [[nodiscard]] std::pair<raw_pub_key, bool> derive_pub_key() const;

        [[nodiscard]] raw_sec_key const &raw_sk() const;
    protected:
        raw_sec_key _sk{};
    };

    /**
     * @note serialize public with ''bd << my_key_pair;'' and secret with ''bd << include_secret << my_key_pair;''.
     */
    class key_pair : public sec_key, public pub_key {
        void overwrite_pub_key();
    public:
        key_pair() = default;
        explicit key_pair(sec_key sk);
        explicit key_pair(raw_sec_key sec_key_raw);
        explicit key_pair(mlab::range<std::uint8_t const *> sec_key_raw);

        [[nodiscard]] pub_key drop_secret_key() const;

        [[nodiscard]] bool encrypt_for(pub_key const &recipient, mlab::bin_data &message) const;
        [[nodiscard]] bool decrypt_from(pub_key const &sender, mlab::bin_data &ciphertext) const;

        [[nodiscard]] bool is_valid() const;

        void generate();
    };

}// namespace ka

namespace ka {

    template <class T, std::size_t Size>
    bool tagged_array<T, Size>::operator==(tagged_array const &other) const {
        return std::equal(std::begin(*this), std::end(*this), std::begin(other));
    }

    template <class T, std::size_t Size>
    bool tagged_array<T, Size>::operator!=(tagged_array const &other) const {
        return not operator==(other);
    }

}//namespace ka
#endif//KEYCARDACCESS_KEYPAIR_HPP
