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

    namespace tagfs {

        template <class... Tn>
        using r = desfire::tag::result<Tn...>;

        /**
         * @addtogroup Error code characterization
         * @brief Checks whether an error code in a result represents an unauthorized operation.
         * @{
         */
        [[nodiscard]] bool is_unauthorized(desfire::error e);

        template <class... Tn>
        [[nodiscard]] bool is_unauthorized(r<Tn...> const &e);
        /**
         * @}
         */

        /**
         * @addtogroup Creating read-only, free-access files
         * @brief Creates a read-only value file with free unencrypted access in the current application.
         * The file can only be deleted afterwards, it is not possible to write on it, only read and it requires no authentication to read.
         * This assumes the app is already selected, the user is already authenticated, if the security settings require so,
         * and file @p fid does not exists.
         * @param fid Id of the file to create
         * @param value Value of the file
         * @return A result representing whether the operation was successful or not.
         * @{
         */
        r<> create_ro_plain_value_file(desfire::tag &tag, desfire::file_id fid, std::int32_t value);
        r<> create_ro_plain_data_file(desfire::tag &tag, desfire::file_id fid, mlab::bin_data const &value);
        /**
         * @}
         */

        /**
         * @brief Makes the current app read only.
         * This is achieved by preventing any change in the master key and configuration, and allowing
         * no key to further change keys.
         * @note If any other key is set up, then those keys will still be able to modify the application. Make
         * sure the current key is the only allowed key in the app.
         * @param list_requires_auth True to require authentication with a key for listing files
         * @return A result representing whether the operation succeeded.
         */
        r<> make_app_ro(desfire::tag &tag, bool list_requires_auth);

        /**
         * @brief Creates an app with a unique, randomized key, suitable for being turned into a read-only app later.
         * @param tag
         * @param aid
         * @return
         */
        [[nodiscard]] r<key_t> create_app_for_ro(desfire::tag &tag, desfire::app_id aid);

        /**
         * @brief Deletes a file in the current app if existing.
         * This assumes the app is already selected and the user is already authenticated, if the security settings require so.
         * @param fid File to delete.
         * @return A result representing whether the operation was successful.
         */
        r<> delete_file_if_exists(desfire::tag &tag, desfire::file_id fid);

        /**
         * @brief Deletes app in if it exists.
         * This assumes that the root app is unlocked, if the security settings require so.
         * @param aid App to delete.
         * @return A result representing whether the operation was successful.
         */
        r<> delete_app_if_exists(desfire::tag &tag, desfire::app_id aid);

        /**
         * @brief Searches for a file id @p fid in the list of files of the current app.
         * This assumes the app is already selected and the user is already authenticated, if the security settings require so.
         * @param fid File to search for.
         * @return A boolean representing whether the file was found (or an error).
         */
        [[nodiscard]] r<bool> does_file_exist(desfire::tag &tag, desfire::file_id fid);

        /**
         * @brief Searches for an app @p aid in the list of applications.
         * This assumes the user is already authenticated, if the security settings require so.
         * @param aid App to search for.
         * @return A boolean representing whether the app was found (or an error).
         */
        [[nodiscard]] r<bool> does_app_exist(desfire::tag &tag, desfire::app_id fid);
    }// namespace tagfs

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


    template <class... Tn>
    bool tagfs::is_unauthorized(r<Tn...> const &e) {
        return (not e) and is_unauthorized(e.error());
    }

    desfire::tag &member_token::tag() const {
        return *_tag;
    }

    desfire::any_key const &member_token::root_key() const {
        return _root_key;
    }

    void member_token::set_root_key(desfire::any_key k) {
        _root_key = std::move(k);
    }
}// namespace ka

#endif//KEYCARDACCESS_MEMBER_TOKEN_HPP
