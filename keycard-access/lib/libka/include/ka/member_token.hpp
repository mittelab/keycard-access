//
// Created by spak on 9/29/22.
//

#ifndef KEYCARDACCESS_MEMBER_TOKEN_HPP
#define KEYCARDACCESS_MEMBER_TOKEN_HPP

#include "config.hpp"
#include "gate.hpp"
#include <desfire/tag.hpp>

namespace ka {

    template <class... Tn>
    using r = desfire::tag::result<Tn...>;


    using tag_key = desfire::key<desfire::cipher_type::aes128>;
    using standard_file_settings = desfire::file_settings<desfire::file_type::standard>;

    class ticket {
        /**
         * @brief Key used to access the enrollment file.
         */
        tag_key _key{1, {}};

        /**
         * @brief Salt used to generate the file content hash.
         */
        std::array<std::uint8_t, 32> _salt{};

    public:
        ticket() = default;
        explicit ticket(std::uint8_t key_no);

        [[nodiscard]] bool verify_file_content(mlab::bin_data const &content, std::string const &holder) const;
        [[nodiscard]] mlab::bin_data get_file_content(std::string const &text) const;
        [[nodiscard]] std::pair<mlab::bin_data, standard_file_settings> get_file(std::string const &text) const;

        /**
         * @brief Generates an enroll ticket with random @ref tag_key and @ref salt.
         */
        [[nodiscard]] static ticket generate(std::uint8_t key_no = 1);

        [[nodiscard]] inline tag_key const &key() const;
        [[nodiscard]] inline std::array<std::uint8_t, 32> const &salt() const;

        /**
         * @note The caller is responsible for selecting the appropriate app and authenticating with the master key.
         * Moreover, it is expected that the key number required by @p t is actually available in the selected
         * application, and that the given application has @ref desfire::key_rights::allowed_to_change_keys set
         * to @ref desfire::same_key. All these conditions are checked via @ref check_app_for_ticket_prerequisite.
         * @note On a successful call, the @ref tag will be in a unauthenticated state, on the current app.
         * @param fid
         * @param t
         * @param text
         * @return
         */
        r<> install(desfire::tag &tag, desfire::file_id fid, std::string const &text) const;

        /**
         * @note The caller is responsible for selecting the appropriate app and authenticating with the master key.
         * Moreover, it is expected that the key number required by @p t is actually available in the selected
         * application, and that the given application has @ref desfire::key_rights::allowed_to_change_keys set
         * to @ref desfire::same_key. All these conditions are checked via @ref check_app_for_prerequisites.
         * @note On a successful call, the @ref tag will be in a unauthenticated state, on the current app.
         * @param fid
         * @param t
         * @param text
         * @return
         */
        r<bool> verify(desfire::tag &tag, desfire::file_id fid, std::string const &text) const;

        /**
         * @note The caller is responsible for selecting the appropriate app and authenticating with the master key.
         * Moreover, it is expected that the key number required by @p t is actually available in the selected
         * application, and that the given application has @ref desfire::key_rights::allowed_to_change_keys set
         * to @ref desfire::same_key. All these conditions are checked via @ref check_app_for_prerequisites.
         * @note On a successful call, the @ref tag will be in a unauthenticated state, on the current app.
         * @param fid
         * @param t
         * @return
         */
        r<> clear(desfire::tag &tag, desfire::file_id fid) const;

        r<> check_app_for_prerequisites(desfire::tag &tag) const;

    };

    enum struct gate_status : std::uint8_t {
        unknown = 0b00,
        enrolled = 0b01,
        auth_ready = 0b10,
        broken = enrolled | auth_ready
    };

    [[nodiscard]] inline bool operator &(gate_status gs1, gate_status gs2);
    [[nodiscard]] inline gate_status operator |(gate_status gs1, gate_status gs2);

    /**
     * @note Conventions: methods do perform authentication with the root tag_key.
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
        static constexpr desfire::file_id gate_authentication_file{0x01};

        using id_t = std::array<std::uint8_t, 7>;

        explicit member_token(desfire::tag &tag);
        member_token(member_token const &) = delete;
        member_token(member_token &&) = default;
        member_token &operator=(member_token const &) = delete;
        member_token &operator=(member_token &&) = default;

        [[nodiscard]] inline desfire::any_key const &root_key() const;
        [[nodiscard]] r<> try_set_root_key(desfire::any_key k);
        [[nodiscard]] r<> unlock();

        [[nodiscard]] inline desfire::tag &tag() const;

        [[nodiscard]] r<std::string> get_holder() const;
        [[nodiscard]] r<std::string> get_publisher() const;
        [[nodiscard]] r<unsigned> get_mad_version() const;

        [[nodiscard]] r<std::vector<gate::id_t>> get_enrolled_gates() const;

        /**
         * @addtogroup Provisioning
         * @{
         */
        r<> setup_root_settings(config const &cfg = system_config());
        r<> setup_mad(std::string const &holder, std::string const &publisher);
        /**
         * @}
         */

        /**
         * @addtogroup Enrollment
         * @{
         */
        /**
          * Creates a new app for this gate, controlled by the master tag_key @p gate_key.
          * This app contains one file, at @ref gate_enroll_file, which is encrypted
          * with the returned tag_key (randomly generated).
          * This file contains the hash of the current card holder @ref get_holder,
          * with a unique (randomly generated) salt, for increased security.
          * At this point, without the returned @ref ticket, cloning or forging
          * the card requires to break the card crypto.
          * @note Using a randomized tag_key with a known file content would be enough to
          * prevent cloning or forging, but in this way we can verify that the card
          * has not been reassigned. By hashing we keep the file size under control, and
          * by adding a salt we strengthen the amount of random bits that need to be guessed.
          */
        r<ticket> enroll_gate(gate::id_t gid, tag_key const &gate_key);
        r<bool> verify_enroll_ticket(gate::id_t gid, ticket const &ticket) const;
        r<> write_auth_file(gate::id_t gid, tag_key const &auth_file_key, std::string const &identity);
        r<bool> authenticate(gate::id_t gid, tag_key const &auth_file_key, std::string const &identity) const;
        r<gate_status> get_gate_status(gate::id_t gid) const;
        /**
          * @}
          */

        /**
         * @brief The ID of the token, as in @ref desfire::tag::get_card_uid().
         */
        [[nodiscard]] r<id_t> id() const;

        /**
         * @brief A differentiated root tag_key to be used with a token.
         * Note that we do not use a pre-shared tag_key for this, rather, we simply derive an
         * token-specific tag_key to differentiate from @ref config::master_key. The user is free to
         * tamper with their token. In the worst case, they might delete the access application
         * and need a redeploy.
         * This uses @ref desfire::kdf_an10922 to differentiate @ref config::master_key into a token-specific
         * root tag_key. It uses the @p token_id and @ref config::differentiation_salt as differentiation input data.
         * @param token_id Id of the token
         * @param cfg Current configuration
         * @return A tag_key which gives root access to the card.
         */
        [[nodiscard]] static tag_key get_default_root_key(id_t token_id, config const &cfg = system_config());
    };

}// namespace ka

namespace ka {

    desfire::tag &member_token::tag() const {
        return *_tag;
    }

    desfire::any_key const &member_token::root_key() const {
        return _root_key;
    }

    tag_key const &ticket::key() const {
        return _key;
    }

    std::array<std::uint8_t, 32> const &ticket::salt() const {
        return _salt;
    }

    bool operator &(gate_status gs1, gate_status gs2) {
        using numeric_t = std::underlying_type_t<gate_status>;
        return (static_cast<numeric_t>(gs1) & static_cast<numeric_t>(gs2)) != 0;
    }

    gate_status operator |(gate_status gs1, gate_status gs2) {
        using numeric_t = std::underlying_type_t<gate_status>;
        return static_cast<gate_status>(static_cast<numeric_t>(gs1) | static_cast<numeric_t>(gs2));
    }

}// namespace ka

#endif//KEYCARDACCESS_MEMBER_TOKEN_HPP
