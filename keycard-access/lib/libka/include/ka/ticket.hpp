//
// Created by spak on 1/8/23.
//

#ifndef KEYCARD_ACCESS_TICKET_HPP
#define KEYCARD_ACCESS_TICKET_HPP

#include <ka/data.hpp>

namespace ka {

    class ticket {
        /**
         * @brief Key used to access the enrollment file.
         */
        key_type _key{1, {}};

        /**
         * @brief Salt used to generate the file content hash.
         */
        ticket_salt _salt{};

    public:
        ticket() = default;
        explicit ticket(std::uint8_t key_no);
        inline ticket(key_type key, ticket_salt salt);

        [[nodiscard]] bool verify_file_content(mlab::bin_data const &content, std::string const &text_to_verify) const;
        [[nodiscard]] mlab::bin_data get_file_content(std::string const &original_text) const;
        [[nodiscard]] std::pair<mlab::bin_data, std_file_settings> get_file(std::string const &original_text) const;

        /**
         * @brief Generates an ticket with random @ref key_type and @ref salt.
         */
        [[nodiscard]] static ticket generate(std::uint8_t key_no);

        [[nodiscard]] inline key_type const &key() const;
        [[nodiscard]] inline ticket_salt const &salt() const;

        /**
         * @note The caller is responsible for selecting the appropriate app and authenticating with the master key.
         * Moreover, it is expected that the key number required by @p t is actually available in the selected
         * application, and that the given application has @ref desfire::key_rights::allowed_to_change_keys set
         * to @ref desfire::same_key. All these conditions are checked via @ref check_app_for_ticket_prerequisite.
         * @note On a successful call, the @ref tag will be in a unauthenticated state, on the current app.
         * @param fid
         * @param t
         * @param original_text
         * @return
         */
        r<> install(desfire::tag &tag, desfire::file_id fid, std::string const &original_text, key_type const &previous_key = key_type{}) const;

        /**
         * @note The caller is responsible for selecting the appropriate app.
         * @note On a successful call, the @ref tag will be in a unauthenticated state, on the current app.
         * @param fid
         * @param t
         * @param text_to_verify
         * @return
         */
        r<bool> verify(desfire::tag &tag, desfire::file_id fid, std::string const &text_to_verify) const;

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
        r<> clear(desfire::tag &tag, desfire::file_id fid, key_type const &previous_key = key_type{}) const;

        r<> check_app_for_prerequisites(desfire::tag &tag) const;
    };

}// namespace ka

namespace ka {

    ticket::ticket(key_type key, ticket_salt salt) : _key{key}, _salt{salt} {}

    key_type const &ticket::key() const {
        return _key;
    }

    ticket_salt const &ticket::salt() const {
        return _salt;
    }

}// namespace ka
#endif//KEYCARD_ACCESS_TICKET_HPP
