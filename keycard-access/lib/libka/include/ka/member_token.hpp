//
// Created by spak on 9/29/22.
//

#ifndef KEYCARDACCESS_MEMBER_TOKEN_HPP
#define KEYCARDACCESS_MEMBER_TOKEN_HPP

#include "config.hpp"
#include "gate.hpp"
#include <desfire/tag.hpp>

namespace ka {

    using key_t = desfire::key<desfire::cipher_type::aes128>;
    using standard_file_settings = desfire::file_settings<desfire::file_type::standard>;

    class enroll_ticket {
        /**
         * @brief Key used to access the enrollment file.
         * @note This has key number 1.
         */
        key_t _key{1, {}};
        std::array<std::uint8_t, 32> _nonce{};

    public:
        enroll_ticket() = default;

        [[nodiscard]] bool verify_enroll_file_content(mlab::bin_data const &content, std::string const &holder) const;
        [[nodiscard]] mlab::bin_data get_enroll_file_content(std::string const &holder) const;
        [[nodiscard]] std::pair<mlab::bin_data, standard_file_settings> get_enroll_file(std::string const &holder) const;
        /**
         * @brief Generates an enroll ticket with random @ref key and @ref nonce.
         */
        [[nodiscard]] static enroll_ticket generate();

        [[nodiscard]] inline key_t const &key() const;
        [[nodiscard]] inline std::array<std::uint8_t, 32> const &nonce() const;
    };

    /**
     * @note Conventions: methods do perform authentication with the root key.
     */
    class member_token {
        /**
         * @note Mutable because interacting with the tag requires non-const access.
         */
        mutable desfire::tag *_tag;
        desfire::any_key _root_key;

    public:
        /**
         * @brief Application directory app id as required by AN10787 §3.10.
         */
        static constexpr desfire::app_id mad_aid{0xff, 0xff, 0xff};
        static constexpr desfire::file_id mad_file_version{0x0};
        static constexpr desfire::file_id mad_file_card_holder{0x1};
        static constexpr desfire::file_id mad_file_card_publisher{0x2};

        static constexpr desfire::file_id gate_enroll_file{0x00};

        template <class... Tn>
        using r = desfire::tag::result<Tn...>;

        using id_t = std::array<std::uint8_t, 7>;

        explicit member_token(desfire::tag &tag);
        member_token(member_token const &) = delete;
        member_token(member_token &&) = default;
        member_token &operator=(member_token const &) = delete;
        member_token &operator=(member_token &&) = default;

        [[nodiscard]] inline desfire::any_key const &root_key() const;
        inline void set_root_key(desfire::any_key k);
        [[nodiscard]] r<> try_set_root_key(desfire::any_key k);

        [[nodiscard]] inline desfire::tag &tag() const;

        [[nodiscard]] r<std::string> get_holder() const;
        [[nodiscard]] r<std::string> get_publisher() const;
        [[nodiscard]] r<unsigned> get_mad_version() const;

        [[nodiscard]] r<std::vector<gate::id_t>> get_enrolled_gates() const;

        /**
         * @addtogroup Provisioning
         * @{
         */
        r<> setup_root_key(config const &cfg = system_config());
        r<> setup_mad(std::string const &holder, std::string const &publisher);
        /**
         * @}
         */

        /**
         * @addtogroup Enrollment
         * @{
         */
        /**
          * Creates a new app for this gate, controlled by the master key @p gate_key.
          * This app contains one file, at @ref gate_enroll_file, which is encrypted
          * with the returned key (randomly generated).
          * This file contains the hash of the current card holder @ref get_holder,
          * with a unique (randomly generated) nonce, for increased security.
          * At this point, without the returned @ref enroll_ticket, cloning or forging
          * the card requires to break the card crypto.
          * @note Using a randomized key with a known file content would be enough to
          * prevent cloning or forging, but in this way we can verify that the card
          * has not been reassigned. By hashing we keep the file size under control, and
          * by adding a nonce we strengthen the amount of random bits that need to be guessed.
          */
        r<enroll_ticket> enroll_gate(gate::id_t gid, key_t const &gate_key);
        r<bool> verify_drop_enroll_ticket(gate::id_t gid, enroll_ticket const &ticket) const;
        r<bool> is_enrolled(gate::id_t gid) const;
        /**
          * @}
          */

        /**
         * @brief The ID of the token, as in @ref desfire::tag::get_card_uid().
         */
        [[nodiscard]] r<id_t> id() const;

        /**
         * @brief A differentiated root key to be used with a token.
         * Note that we do not use a pre-shared key for this, rather, we simply derive an
         * token-specific key to differentiate from @ref config::master_key. The user is free to
         * tamper with their token. In the worst case, they might delete the access application
         * and need a redeploy.
         * This uses @ref desfire::kdf_an10922 to differentiate @ref config::master_key into a token-specific
         * root key. It uses the @p token_id and @ref config::differentiation_salt as differentiation input data.
         * @param token_id Id of the token
         * @param cfg Current configuration
         * @return A key which gives root access to the card.
         */
        [[nodiscard]] static key_t get_default_root_key(id_t token_id, config const &cfg = system_config());
    };

}// namespace ka

namespace ka {

    desfire::tag &member_token::tag() const {
        return *_tag;
    }

    desfire::any_key const &member_token::root_key() const {
        return _root_key;
    }

    void member_token::set_root_key(desfire::any_key k) {
        _root_key = std::move(k);
    }
    key_t const &enroll_ticket::key() const {
        return _key;
    }

    std::array<std::uint8_t, 32> const &enroll_ticket::nonce() const {
        return _nonce;
    }

}// namespace ka

#endif//KEYCARDACCESS_MEMBER_TOKEN_HPP
