//
// Created by spak on 10/5/22.
//

#ifndef KEYCARDACCESS_KEY_PAIR_HPP
#define KEYCARDACCESS_KEY_PAIR_HPP

#include <ka/data.hpp>

namespace ka {

    struct pub_key_tag {};
    struct sec_key_tag {};

    using raw_pub_key = mlab::tagged_array<pub_key_tag, 32>;
    using raw_sec_key = mlab::tagged_array<sec_key_tag, 32>;


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

        /**
         * @brief A differentiated root key to be used as the root key of a token.
         * The user is free to know this and to tamper with the token, in the worst case it will delete the application.
         * @param token_id Id of the token
         * @return A key_type which gives root access to the card.
         */
        [[nodiscard]] token_root_key derive_token_root_key(token_id const &id) const;

        /**
         * @brief A differentiated app key to be used as the master of a token app.
         * @param token_id Id of the token
         * @return A key_type which gives root access to the card.
         */
        [[nodiscard]] gate_app_master_key derive_gate_app_master_key(token_id const &id) const;

    protected:
        raw_sec_key _sk{};
    };

    struct randomize_t {};
    static constexpr randomize_t randomize{};

    struct pwhash_t {};
    static constexpr pwhash_t pwhash{};

    class key_pair : public sec_key, public pub_key {
        void overwrite_pub_key();

    public:
        key_pair() = default;
        explicit key_pair(randomize_t);
        explicit key_pair(sec_key sk);
        explicit key_pair(raw_sec_key sec_key_raw);
        explicit key_pair(mlab::range<std::uint8_t const *> sec_key_raw);
        key_pair(pwhash_t, std::string const &password);

        [[nodiscard]] pub_key drop_secret_key() const;

        [[nodiscard]] bool encrypt_for(pub_key const &recipient, mlab::bin_data &message) const;
        [[nodiscard]] bool decrypt_from(pub_key const &sender, mlab::bin_data &ciphertext) const;

        [[nodiscard]] bool is_valid() const;

        void generate_random();
        void generate_from_pwhash(std::string const &password);
    };

}// namespace ka

#endif//KEYCARDACCESS_KEY_PAIR_HPP
