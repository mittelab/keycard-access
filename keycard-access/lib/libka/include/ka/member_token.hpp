//
// Created by spak on 9/29/22.
//

#ifndef KEYCARDACCESS_MEMBER_TOKEN_HPP
#define KEYCARDACCESS_MEMBER_TOKEN_HPP

#include <ka/data.hpp>
#include <desfire/tag_responder.hpp>
#include <desfire/esp32/cipher_provider.hpp>

namespace ka {

    class member_token;
    class gate;
    class key_pair;
    class pub_key;
    struct gate_config;
    class keymaker;

    /**
     * @brief Specialization of a token responder which casts a @ref desfire::tag into a @ref member_token
     */
    struct member_token_responder : public virtual desfire::tag_responder<desfire::esp32::default_cipher_provider> {
        pn532::post_interaction interact_with_tag(desfire::tag &tag) override;

        virtual pn532::post_interaction interact_with_token(member_token &token) = 0;
    };

    /**
     * @note Conventions: methods do perform authentication with the root key_type.
     */
    class member_token {
        /**
         * @note Mutable because interacting with the tag requires non-const access.
         */
        mutable desfire::tag *_tag;

        /**
         * @param aid App Id
         * @param fid File Id
         * @param mkey App master key
         * @param target_key_no Key number that will have exclusive read access to the file.
         * @param data Data to write
         * @param check_app If true, it will run @ref check_gate_app on @p aid
         * @return
         *  - @ref desfire::error::parameter_error If @p mkey does not have key number 0 or @p aid does not pass @ref gate_id::is_valid_gate_app
         *  - @ref desfire::error::app_integrity_error If the app settings are incorrect
         *  - @ref desfire::error::permission_denied If @p mkey cannot login
         *  - @ref desfire::error::app_not_found If the app was not found
         *  - Any other @ref desfire::error in case of communication failure.
         */
        r<> write_gate_file_internal(desfire::app_id aid, desfire::file_id fid, gate_app_master_key const &mkey, std::uint8_t target_key_no, mlab::bin_data const &data, bool check_app);

        /**
         * @param aid App Id
         * @param fid File Id
         * @param key Key that is supposed to open for reading @p fid
         * @param check_app If true, it will run @ref check_gate_app on @p aid
         * @param check_file If true, it will run @ref check_gate_file on @o fid
         * @return The file content if everything was successful, otherwise
         *  - @ref desfire::error::app_integrity_error If the app has incorrect settings.
         *  - @ref desfire::error::file_integrity_error If the file has incorrect settings.
         *  - @ref desfire::error::permission_denied If @p key is incorrect
         *  - @ref desfire::error::app_not_found If the app was not found
         *  - @ref desfire::error::file_not_found If the file was not found
         *  - Any other @ref desfire::error in case of communication failure.
         */
        [[nodiscard]] r<mlab::bin_data> read_gate_file_internal(desfire::app_id aid, desfire::file_id fid, gate_token_key const &key, bool check_app, bool check_file) const;

        /**
         * @note The app must already be selected.
         * @param fid File id
         * @param key_no Key expected to have exclusive read access to the file.
         * @param expect_exists If true, a message will be issued in case the file does not exist.
         * @return
         *  - true if the file exists and the settings are correct
         *  - false if the file exists but the settings are incorrect
         *  - @ref desfire::error::app_integrity_error if the current authentication status did not allow to query the file's
         *      settings (implies that the app's settings are incorrect).
         *  - @ref desfire::error::file_not_found if the file was not found
         *  - Any other @ref desfire::error in case of communication failure.
         */
        [[nodiscard]] r<bool> check_gate_file_internal(desfire::file_id fid, std::uint8_t key_no, bool expect_exists) const;

        /**
         * @param aid App id
         * @param fid File id
         * @param key_no Key expected to have exclusive read access to the file.
         * @param check_app If true, it will run @ref check_gate_app on @p aid
         * @param expect_exists If true, a message will be issued in case the app or the file does not exist.
         * @return
         *  - true if the file exists and the settings are correct
         *  - false if the file exists but the settings are incorrect
         *  - @ref desfire::error::app_integrity_error if the settings of the app are incorrect
         *  - @ref desfire::error::app_not_found if the app was not found
         *  - @ref desfire::error::file_not_found if the file was not found
         *  - @ref desfire::error::parameter_error if @ref aid did not pass @ref gate_id::is_valid_gate_app
         *  - Any other @ref desfire::error in case of communication failure.
         */
        [[nodiscard]] r<bool> check_gate_file_internal(desfire::app_id aid, desfire::file_id fid, std::uint8_t key_no, bool check_app, bool expect_exists) const;

        /**
         * @return Any @ref desfire::error in case of communication failure.
         */
        r<> setup_root_internal(token_root_key const &rkey, bool format);

        /**
         *
         * @param aid App Id
         * @param fid File Id
         * @param key Key that is supposed to open for reading @p fid
         * @param kp Key pair of the target of this file, either the @ref keymaker's or the @ref gate's
         * @param pk Public key of the @ref keymaker
         * @param check_app If true, it will run @ref check_gate_app on @p aid
         * @param check_file If true, it will run @ref check_gate_file on @o fid
         * @return The identity if everything was successful, otherwise
         *  - @ref desfire::error::app_integrity_error If the app has incorrect settings.
         *  - @ref desfire::error::file_integrity_error If the file has incorrect settings.
         *  - @ref desfire::error::permission_denied If @p key is incorrect
         *  - @ref desfire::error::app_not_found If the app was not found
         *  - @ref desfire::error::file_not_found If the file was not found
         *  - @ref desfire::error::crypto_error If it was not possible to decrypt the identity.
         *  - @ref desfire::error::malformed If it was not possible to parse the identity.
         *  - Any other @ref desfire::error in case of communication failure.
         */
        [[nodiscard]] r<identity> read_encrypted_gate_file_internal(desfire::app_id aid, desfire::file_id fid, gate_token_key const &key, key_pair const &kp, pub_key const &pk, bool check_app, bool check_file) const;

        /**
         * @param aid App Id
         * @param fid File Id
         * @param mkey App master key
         * @param target_key_no Key number that will have exclusive read access to the file.
         * @param data Data to write
         * @param kp Key pair of the @ref keymaker
         * @param pk Public key to target in this file, either the @ref keymaker's or the @ref gate's
         * @param id Identity to write
         * @param check_app If true, it will run @ref check_gate_app on @p aid
         * @return
         *  - @ref desfire::error::parameter_error If @p mkey does not have key number 0.
         *  - @ref desfire::error::app_integrity_error If the app settings are incorrect
         *  - @ref desfire::error::permission_denied If @p mkey cannot login
         *  - @ref desfire::error::app_not_found If the app was not found
         *  - @ref desfire::error::crypto_error If it was not possible to encrypt the identity.
         *  - Any other @ref desfire::error in case of communication failure.
         */
        r<> write_encrypted_gate_file_internal(desfire::app_id aid, desfire::file_id fid, gate_app_master_key const &mkey, std::uint8_t target_key_no, key_pair const &kp, pub_key const &pk, identity const &id, bool check_app);

        /**
         * @param expect_exists If true, a message will be issued in case the app does not exist.
         * @return
         *  - true if the login succeeded
         *  - false if the app was selected, but login did not succeed.
         *  - @ref desfire::error::app_not_found if the app was not found
         *  - Any other @ref desfire::error in case of communication failure.
         */
        [[nodiscard]] r<bool> check_key_internal(desfire::any_key const &key, desfire::app_id aid, bool expect_exists) const;

        /**
         *
         * @param key Key that is supposed to open for reading @p g's file
         * @param kp Key pair of the @p keymaker's
         * @param g Public gate configuration.
         * @param id Identity that is expected to be found in the gate file
         * @param check_app If true, it will run @ref check_gate_app
         * @param check_file If true, it will run @ref check_gate_file
         * @return
         *  - true if the file exists, is readable and the expected content
         *  - false if the file exists, is readable but the content does not match
         *  - @ref desfire::error::app_integrity_error If the app has incorrect settings.
         *  - @ref desfire::error::file_integrity_error If the file has incorrect settings.
         *  - @ref desfire::error::permission_denied If @p key is incorrect
         *  - @ref desfire::error::app_not_found If the app was not found
         *  - @ref desfire::error::file_not_found If the file was not found
         *  - @ref desfire::error::crypto_error If it was not possible to encrypt @p id
         *  - Any other @ref desfire::error in case of communication failure.
         */
        [[nodiscard]] r<bool> check_encrypted_gate_file_internal(gate_token_key const &key, key_pair const &kp, gate_config const &g, identity const &id, bool check_app, bool check_file) const;

        /**
         * @param key_no only used when @p check_file is true
         * @return
         *  - true if the gate app and gate file exists and its settings are correct
         *  - false if the gate app or the gate file do not exist
         *  - @ref desfire::error::app_integrity_error if the app exists but its settings are incorrect
         *  - @ref desfire::error::file_integrity_error if the app and file exists but its settings are incorrect
         *  - Any other @ref desfire::error in case of communication failure.
         */
        [[nodiscard]] r<bool> is_enrolled_internal(desfire::app_id aid, desfire::file_id fid, std::uint8_t key_no, bool check_app, bool check_file) const;

        /**
         * @tparam Fn Must have signature `r<> fn(desfire::app_id)`.
         * @param check_app If true, it will call @ref check_gate_app on each potential gate app, and skips those that fail the tests.
         * @return A range of contiguous gate apps, or any other @ref desfire::error in case of communication failure.
         */
        template <class Fn>
        r<> list_gate_apps_internal(bool check_app, Fn &&app_action) const;
    public:
        explicit member_token(desfire::tag &tag);

        /**
         * @addtogroup Low level member token commands, checking
         * @{
         */

        /**
         * @brief Checks if the given root key is a valid root key, without verbose logging.
         * @return
         *  - true if the login succeeded
         *  - false if the app was selected, but login did not succeed.
         *  - Any other @ref desfire::error in case of communication failure.
         */
        [[nodiscard]] r<bool> check_root_key(desfire::any_key const &key) const;

        /**
         * @brief Checks that the tag root configuration is suitable to be a gate tag.
         * A suitable gate tag does not allow listing, create or delete without authentication.
         * This can be used to test the root key as well.
         * @param rkey Token root key.
         * @return
         *  - true if @p rkey works and the root app's settings are correct
         *  - false if @p rkey works, but the root's settings are incorrect
         *  - @ref desfire::error::permission_denied if @p rkey is incorrect
         *  - Any other @ref desfire::error in case of communication failure.
         */
        [[nodiscard]] r<bool> check_root(token_root_key const &rkey) const;

        /**
         * @brief Checks that the app @p aid has valid settings to be a gate app.
         * A gate app must have exactly @ref gate_id::gates_per_app extra keys, allow dir access without authentication, do not allow
         * config change nor master key change, and have as the only key able to change other keys the master key. Moreover, it must
         * be encrypted with AES128.
         * @param aid App to test. This must pass @ref gate_id::is_valid_gate_app, otherwise @ref desfire::error::parameter_error is returned.
         * @param expect_exists If true, a message will be issued in case the app does not exist.
         * @return
         *  - true if @p aid exists and its settings are correct
         *  - false if @p aid exists, but its settings are incorrect
         *  - @ref desfire::error::app_not_found if @p aid does not exist
         *  - Any other @ref desfire::error in case of communication failure.
         */
        [[nodiscard]] r<bool> check_gate_app(desfire::app_id aid, bool expect_exists = false) const;

        /**
         * @brief Checks that the gate file identified by @p gid has valid settings to be a gate file.
         * A gate file must be a standard data file, with ciphered access, with only one available access right, which is reading by
         * a single key, which must match @ref gate_id::key_no.
         * @param gid Gate ID identifying the gate file.
         * @param check_app If true, it will run @ref check_gate_app on @p aid
         * @param expect_exists If true, a message will be issued in case the app or the file does not exist.
         * @return
         *  - true if the file exists and the settings are correct
         *  - false if the file exists but the settings are incorrect
         *  - @ref desfire::error::app_integrity_error if the settings of the app are incorrect
         *  - @ref desfire::error::app_not_found if the app was not found
         *  - @ref desfire::error::file_not_found if the file was not found
         *  - Any other @ref desfire::error in case of communication failure.
         */
        [[nodiscard]] r<bool> check_gate_file(gate_id gid, bool check_app, bool expect_exists = false) const;

        /**
         * @brief Checks that the master file, i.e. file 0 at @ref gate_id::aid_range_begin, has valid settings to be a gate file.
         * A gate file must be a standard data file, with ciphered access, with only one available access right, which is reading by
         * a single key, which must match the master key with key number 0.
         * @param check_app If true, it will run @ref check_gate_app on @p aid
         * @param expect_exists If true, a message will be issued in case the app or the file does not exist.
         * @return
         *  - true if the file exists and the settings are correct
         *  - false if the file exists but the settings are incorrect
         *  - @ref desfire::error::app_integrity_error if the settings of the app are incorrect
         *  - @ref desfire::error::app_not_found if the app was not found
         *  - @ref desfire::error::file_not_found if the file was not found
         *  - Any other @ref desfire::error in case of communication failure.
         */
        [[nodiscard]] r<bool> check_master_file(bool check_app, bool expect_exists = false) const;

        /**
         * @brief Selects the gate app @ref gate_id::app, and tries to login with the given key @p key.
         * @param gid Group ID identifying the app.
         * @param key Key to use to login. This must have @ref key_type::key_number equal to @ref gate_id::key_no,
         *  otherwise @ref desfire::error::parameter_error is returned.
         * @param expect_exists If true, a message will be issued in case the app does not exist.
         * @return
         *  - true if the login succeeded
         *  - false if the app was selected, but login did not succeed.
         *  - @ref desfire::error::app_not_found if the app was not found
         *  - @ref desfire::error::parameter_error if the the key number does not match @p gid
         *  - Any other @ref desfire::error in case of communication failure.
         */
        [[nodiscard]] r<bool> check_gate_key(gate_id gid, gate_token_key const &key, bool expect_exists = false) const;

        /**
         * @brief Selects the gate app @ref gate_id::aid_range_begin, and tries to login with the given key @p mkey.
         * @param mkey Key to use to login. This must have @ref key_type::key_number equal to 0,
         *  otherwise @ref desfire::error::parameter_error is returned.
         * @param aid App to test. This must pass @ref gate_id::is_valid_gate_app,
         *  otherwise @ref desfire::error::parameter_error is returned.
         * @param expect_exists If true, a message will be issued in case the app does not exist.
         * @return
         *  - true if the login succeeded
         *  - false if the app was selected, but login did not succeed.
         *  - @ref desfire::error::app_not_found if the app was not found
         *  - @ref desfire::error::parameter_error if the the key number is not 0 or of @p aid does not pass @ref gate_id::is_valid_gate_app
         *  - Any other @ref desfire::error in case of communication failure.
         */
        [[nodiscard]] r<bool> check_master_key(gate_app_master_key const &mkey, desfire::app_id aid = gate_id::first_aid, bool expect_exists = false) const;

        /**
         * @}
         */


        /**
         * @addtogroup Low level member token commands, read and write
         * @{
         */

        /**
         * @brief Reads the content of a gate file identified by @ref gid using @ref key.
         * It does not expect that the gate app or file exists, returning the corresponding error codes in case of failure.
         * @param gid Gate ID.
         * @param key Key to use to read the file. This must have @ref key_type::key_number equal to @ref gate_id::key_no,
         *  otherwise @ref desfire::error::parameter_error is returned.
         * @param check_app If true, it will call @ref check_gate_app on @ref gate_id::app and in case of failure, it will return
         *  @ref desfire::error::app_integrity_error.
         * @param check_file If true, it will call @ref check_gate_file on @ref gate_id::file and in case of failure, it will return
         *  @ref desfire::error::file_integrity_error.
         * @return The file content if everything was successful, otherwise
         *  - @ref desfire::error::app_integrity_error If the app has incorrect settings.
         *  - @ref desfire::error::file_integrity_error If the file has incorrect settings.
         *  - @ref desfire::error::permission_denied If @p key is incorrect
         *  - @ref desfire::error::app_not_found If the app was not found
         *  - @ref desfire::error::file_not_found If the file was not found
         *  - @ref desfire::error::parameter_error if the the key number does not match @p gid
         *  - Any other @ref desfire::error in case of communication failure.
         */
        [[nodiscard]] r<mlab::bin_data> read_gate_file(gate_id gid, gate_token_key const &key, bool check_app, bool check_file) const;

        /**
         * @brief Reads the content of the master file, i.e. file 0 at @ref gate_id::aid_range_begin.
         * This file is exclusively set up by the programmer for its own identification.
         * @param mkey Gate app master key, the only one which can access the master file. This must have @ref key_type::key_number 0,
         *  otherwise @ref desfire::error::parameter_error is returned.
         * @param check_app If true, it will call @ref check_gate_app on @ref gate_id::app and in case of failure, it will return
         *  @ref desfire::error::app_integrity_error.
         * @param check_file If true, it will call @ref check_gate_file on @ref gate_id::file and in case of failure, it will return
         *  @ref desfire::error::file_integrity_error.
         * @return The file content if everything was successful, otherwise
         *  - @ref desfire::error::app_integrity_error If the app has incorrect settings.
         *  - @ref desfire::error::file_integrity_error If the file has incorrect settings.
         *  - @ref desfire::error::permission_denied If @p key is incorrect
         *  - @ref desfire::error::app_not_found If the app was not found
         *  - @ref desfire::error::file_not_found If the file was not found
         *  - @ref desfire::error::parameter_error if the the key number is not 0
         *  - Any other @ref desfire::error in case of communication failure.
         */
        [[nodiscard]] r<mlab::bin_data> read_master_file(gate_app_master_key const &mkey, bool check_app, bool check_file) const;


        /**
         * @brief Writes the given content into a gate file.
         * A file with the same id is allowed to exist, in that case it will be deleted.
         * @see check_gate_file
         * @param gid Gate ID identifying the gate file.
         * @param mkey Master key for the gate app. Necessary to delete and create files.
         * @param data Data to store inside the gate file.
         * @param check_app If true, it will call @ref check_gate_app on @ref gate_id::app and in case of failure, it will return
         *  @ref desfire::error::app_integrity_error.
         * @return
         *  - @ref desfire::error::parameter_error If @p mkey does not have key number 0.
         *  - @ref desfire::error::app_integrity_error If the app settings are incorrect
         *  - @ref desfire::error::permission_denied If @p mkey cannot login
         *  - @ref desfire::error::app_not_found If the app was not found
         *  - Any other @ref desfire::error in case of communication failure.
         */
        r<> write_gate_file(gate_id gid, gate_app_master_key const &mkey, mlab::bin_data const &data, bool check_app);

        /**
         * @brief Writes the given content into the master file, i.e. file 0 at @ref gate_id::aid_range_begin.
         * A file with the same id is allowed to exist, in that case it will be deleted.
         * @see check_gate_file
         * @param mkey Master key for the gate app. Necessary to delete and create files.
         * @param data Data to store inside the gate file.
         * @param check_app If true, it will call @ref check_gate_app on @ref gate_id::app and in case of failure, it will return
         *  @ref desfire::error::app_integrity_error.
         * @return
         *  - @ref desfire::error::parameter_error If @p mkey does not have key number 0.
         *  - @ref desfire::error::app_integrity_error If the app settings are incorrect
         *  - @ref desfire::error::permission_denied If @p mkey cannot login
         *  - @ref desfire::error::app_not_found If the app was not found
         *  - Any other @ref desfire::error in case of communication failure.
         */
        r<> write_master_file(gate_app_master_key const &mkey, mlab::bin_data const &data, bool check_app);

        /**
         * @}
         */

        /**
         * @addtogroup Low level member token commands, management
         * @{
         */

        /**
         * @brief Retrieved the token id.
         * @returns The token id or any other @ref desfire::error in case of communication failure.
         */
        [[nodiscard]] r<token_id> get_id() const;

        /**
         * @brief Creates a gate app at the requested @p aid. An app with that id must not exist already.
         * @see check_gate_app
         * @param aid Application ID. Must pass @ref gate_id::is_valid_gate_app, otherwise @ref desfire::error::parameter_error is returned.
         * @param rkey Root key for the token. Necessary to create apps.
         * @param mkey Master key of the gate app. This will be configured as the master key of the app.
         * @return
         *  - @ref desfire::error::permission_denied If @p rkey does not authenticate at the PICC root level
         *  - @ref desfire::error::parameter_error If @p mkey's key number is not 0
         *  - Any other @ref desfire::error in case of communication failure.
         */
        r<> create_gate_app(desfire::app_id aid, token_root_key const &rkey, gate_app_master_key const &mkey);

        /**
         * @brief Changes the gate key associated to the gate file @p gid to @p key.
         * @param gid Group ID identifying the gate file.
         * @param mkey Master key to use to change the gate key. This must have @ref key_type::key_number equal to 0,
         *  otherwise @ref desfire::error::parameter_error is returned.
         * @param key Key to update. This must have @ref key_type::key_number equal to @ref gate_id::key_no,
         *  otherwise @ref desfire::error::parameter_error is returned.
         * @param check_app If true, it will call @ref check_gate_app on @ref gate_id::app and in case of failure, it will return
         *  @ref desfire::error::app_integrity_error.
         * @return
         *  - @ref desfire::error::parameter_error If @p mkey's key number is not 0
         *  - @ref desfire::error::permission_denied If @p mkey does not authenticate
         *  - @ref desfire::error::app_integrity_error If the app settings are incorrect
         *  - Any other @ref desfire::error in case of communication failure.
         */
        r<> enroll_gate_key(gate_id gid, gate_app_master_key const &mkey, gate_token_key const &key, bool check_app);

        /**
         * @brief Lists all gates app existing on this card.
         * Does not require any password, as the gate apps can be selected one by one.
         * @param check_app If true, it will call @ref check_gate_app on each potential gate app, and skips those that fail the tests.
         * @return A range of contiguous gate apps, or any other @ref desfire::error in case of communication failure.
         */
        [[nodiscard]] r<mlab::range<desfire::app_id>> list_gate_apps(bool check_app) const;

        /**
         * @brief Makes sure a gate app @p aid exists and has correct settings and keys.
         * Creates a gate app if it does not exists, otherwise runs @ref check_gate_app
         * as well as @ref check_master_key on it.
         * @see check_gate_app
         * @param aid Application ID. Must pass @ref gate_id::is_valid_gate_app, otherwise @ref desfire::error::parameter_error is returned.
         * @param rkey Token root key, necessary to create and delete applications.
         * @param mkey Master key to use to create the existing key. This must have @ref key_type::key_number equal to 0,
         *  otherwise @ref desfire::error::parameter_error is returned.
         * @return
         *  - @ref desfire::error::parameter_error if @p aid did not pass @ref gate_id::is_valid_gate_app or if @p mkey's key number is not 0
         *  - @ref desfire::error::permission_denied if one of @p rkey or @p mkey does not authenticate the corresponding app
         *  - @ref desfire::error::app_integrity_error If an app already exists and its settings are incorrect
         *  - Any other @ref desfire::error in case of communication failure.
         */
        r<> ensure_gate_app(desfire::app_id aid, token_root_key const &rkey, gate_app_master_key const &mkey);

        /**
         * @brief Ensures that the root key and the root settings are suitable for a gate app.
         * The method tries the specified root key as well as the default key.
         * @see check_root
         * @param rkey Root key to set.
         * @param format Specify true to format the picc. This will erase all data.
         * @return
         *  - @ref desfire::error::permission_denied if it was not possible to authenticate with any root key
         *  - Any other @ref desfire::error in case of communication failure.
         */
        r<> setup_root(token_root_key const &rkey, bool format);

        /**
         * @brief Ensures that the root key and the root settings are suitable for a gate app.
         * The method tries the specified root key, @p previous_rkey, as well as the default key.
         * @see check_root
         * @param rkey Root key to set.
         * @param format Specify true to format the picc. This will erase all data.
         * @param previous_rkey Previous root key, if known
         * @return
         *  - @ref desfire::error::permission_denied if it was not possible to authenticate with any root key
         *  - Any other @ref desfire::error in case of communication failure.
         */
        r<> setup_root(token_root_key const &rkey, bool format, desfire::any_key const &previous_rkey);
        /**
         * @}
         */

        /**
         * @addtogroup Low level member token commands, encrypted write
         * @{
         */

        /**
         * @brief Writes the given identity encrypted into the gate file.
         * A file with the same id is allowed to exist, in that case it will be deleted.
         * This method will retrieve the @ref token_id with @ref get_id, then derive the correct @ref gate_app_master_key
         * from @ref keymaker::keys's secret key using @ref sec_key::derive_gate_app_master_key, encrypt the identity
         * for the given @p g, and then write the encrypted content through @ref write_gate_file.
         * In case of encryption failure, @ref desfire::error::crypto_error is returned.
         * @see check_gate_file
         * @param km Keymaker.
         * @param g Public gate configuration.
         * @param id Identity to write.
         * @param check_app If true, it will call @ref check_gate_app on @ref gate_id::app and in case of failure, it will return
         *  @ref desfire::error::app_integrity_error.
         * @return The token id that was used to generate keys, or
         *  - @ref desfire::error::parameter_error If @p mkey does not have key number 0.
         *  - @ref desfire::error::app_integrity_error If the app settings are incorrect
         *  - @ref desfire::error::permission_denied If @p mkey cannot login
         *  - @ref desfire::error::app_not_found If the app was not found
         *  - @ref desfire::error::crypto_error If it was not possible to encrypt the identity.
         *  - Any other @ref desfire::error in case of communication failure.
         */
        r<token_id> write_encrypted_gate_file(keymaker const &km, gate_config const &g, identity const &id, bool check_app);

        /**
         * @brief Writes the given identity encrypted into the master file.
         * A file with the same id is allowed to exist, in that case it will be deleted.
         * This method will retrieve the @ref token_id with @ref get_id, then derive the correct @ref gate_app_master_key
         * from @ref keymaker::keys's secret key using @ref sec_key::derive_gate_app_master_key, encrypt the identity
         * for the given @p km, and then write the encrypted content through @ref write_master_file.
         * In case of encryption failure, @ref desfire::error::crypto_error is returned.
         * @see check_gate_file
         * @param km Keymaker.
         * @param id Identity to write.
         * @param check_app If true, it will call @ref check_gate_app on @ref gate_id::app and in case of failure, it will return
         *  @ref desfire::error::app_integrity_error.
         * @return The token id that was used to generate keys, or
         *  - @ref desfire::error::parameter_error If @p mkey does not have key number 0.
         *  - @ref desfire::error::app_integrity_error If the app settings are incorrect
         *  - @ref desfire::error::permission_denied If @p mkey cannot login
         *  - @ref desfire::error::app_not_found If the app was not found
         *  - @ref desfire::error::crypto_error If it was not possible to encrypt the identity.
         *  - Any other @ref desfire::error in case of communication failure.
         */
        r<token_id> write_encrypted_master_file(keymaker const &km, identity const &id, bool check_app);
        /**
         * @}
         */


        /**
         * @addtogroup High level member token commands
         * @{
         */

        /**
         * @brief Tests if a gate is enrolled.
         * @param gid Gate ID
         * @param check_app If true, it will call @ref check_gate_app on @ref gate_id::app and in case of failure, it will return
         *  @ref desfire::error::app_integrity_error.
         * @param check_file If true, it will call @ref check_gate_file on @ref gate_id::file and in case of failure, it will return
         *  @ref desfire::error::file_integrity_error.
         * @note Differs from @ref check_gate_file in the sense that it returns false if the file or app does not exist; however, if
         *  @p check_file is false, this method is optimized to run less commands than @ref check_gate_file.
         * @return
         *  - true if the gate app and gate file exists and its settings are correct
         *  - false if the gate app or the gate file do not exist
         *  - @ref desfire::error::app_integrity_error if the app exists but its settings are incorrect
         *  - @ref desfire::error::file_integrity_error if the app and file exists but its settings are incorrect
         *  - Any other @ref desfire::error in case of communication failure.
         */
        [[nodiscard]] r<bool> is_gate_enrolled(gate_id gid, bool check_app, bool check_file) const;

        /**
         * @brief Tests if the master file and its app exist.
         * @param check_app If true, it will call @ref check_gate_app on @ref gate_id::app and in case of failure, it will return
         *  @ref desfire::error::app_integrity_error.
         * @param check_file If true, it will call @ref check_gate_file on @ref gate_id::file and in case of failure, it will return
         *  @ref desfire::error::file_integrity_error.
         * @note Differs from @ref check_master_file in the sense that it returns false if the file or app does not exist; however, if
         *  @p check_file is false, this method is optimized to run less commands than @ref check_master_file.
         * @return
         *  - true if the gate app and master file exists and its settings are correct
         *  - false if the gate app or the master file do not exist
         *  - @ref desfire::error::app_integrity_error if the app exists but its settings are incorrect
         *  - @ref desfire::error::file_integrity_error if the app and file exists but its settings are incorrect
         *  - Any other @ref desfire::error in case of communication failure.
         */
        [[nodiscard]] r<bool> is_master_enrolled(bool check_app, bool check_file) const;

        /**
         * @brief Lists all gates that are enrolled in this card (according to the existence of gate files).
         * Does not require any password, as the gate apps are listable without authentication. All apps and files that are
         * not readable or not checkable are simply skipped (and a warning issued).
         * @param check_app If true, it will call @ref check_gate_app on each potential gate app, and skips those that fail the tests.
         * @param check_file If true, it will call @ref check_gate_file on each potential gate file, and skips those that fail the tests.
         * @return A range of gate ids which have an app and file, or any other @ref desfire::error in case of communication failure.
         */
        [[nodiscard]] r<std::vector<gate_id>> list_gates(bool check_app, bool check_file) const;

        /**
         * @brief Reads the identity from a gate file.
         * It does not expect that the gate app or file exists, returning the corresponding error codes in case of failure.
         * This method will retrieve the @ref token_id with @ref get_id, then derive the correct @ref gate_token_key
         * from @ref gate::base_key using @ref gate_base_key::derive_token_key, use that to open the raw content
         * through @ref read_gate_file, and then decrypt the content using @ref gate::keys.
         * In case of decryption failure, @ref desfire::error::crypto_error is returned.
         * In case of parsing error, @ref desfire::error::malformed is returned.
         * @param g Gate. Must be configured, otherwise @ref desfire::error::parameter_error is returned.
         * @param check_app If true, it will call @ref check_gate_app on @ref gate_id::app and in case of failure, it will return
         *  @ref desfire::error::app_integrity_error.
         * @param check_file If true, it will call @ref check_gate_file on @ref gate_id::file and in case of failure, it will return
         *  @ref desfire::error::file_integrity_error.
         * @return The identity if everything was successful and the token id that was used to generate keys, otherwise
         *  - @ref desfire::error::app_integrity_error If the app has incorrect settings.
         *  - @ref desfire::error::file_integrity_error If the file has incorrect settings.
         *  - @ref desfire::error::permission_denied If the derived key did not open the file
         *  - @ref desfire::error::app_not_found If the app was not found
         *  - @ref desfire::error::file_not_found If the file was not found
         *  - @ref desfire::error::crypto_error If it was not possible to decrypt the identity.
         *  - @ref desfire::error::malformed If it was not possible to parse the identity.
         *  - Any other @ref desfire::error in case of communication failure.
         */
        [[nodiscard]] r<identity, token_id> read_encrypted_gate_file(gate const &g, bool check_app, bool check_file) const;

        /**
         * @brief Reads the identity from master file, i.e. file 0 at @ref gate_id::aid_range_begin.
         * This file is exclusively set up by the programmer for its own identification.
         * It does not expect that the gate app or file exists, returning the corresponding error codes in case of failure.
         * This method will retrieve the @ref token_id with @ref get_id, then derive the correct @ref gate_app_master_key
         * from @ref keymaker::keys's secret key using @ref sec_key::derive_gate_app_master_key, use that to open the raw content
         * through @ref read_master_file, and then decrypt the content using @ref keymaker::keys.
         * In case of decryption failure, @ref desfire::error::crypto_error is returned.
         * In case of parsing error, @ref desfire::error::malformed is returned.
         * @param km Keymaker.
         * @param check_app If true, it will call @ref check_gate_app on @ref gate_id::app and in case of failure, it will return
         *  @ref desfire::error::app_integrity_error.
         * @param check_file If true, it will call @ref check_gate_file on @ref gate_id::file and in case of failure, it will return
         *  @ref desfire::error::file_integrity_error.
         * @return The identity if everything was successful and the token id that was used to generate keys, otherwise
         *  - @ref desfire::error::app_integrity_error If the app has incorrect settings.
         *  - @ref desfire::error::file_integrity_error If the file has incorrect settings.
         *  - @ref desfire::error::permission_denied If the derived key did not open the file
         *  - @ref desfire::error::app_not_found If the app was not found
         *  - @ref desfire::error::file_not_found If the file was not found
         *  - @ref desfire::error::crypto_error If it was not possible to decrypt the identity.
         *  - @ref desfire::error::malformed If it was not possible to parse the identity.
         *  - Any other @ref desfire::error in case of communication failure.
         */
        [[nodiscard]] r<identity, token_id> read_encrypted_master_file(keymaker const &km, bool check_app, bool check_file) const;

        /**
         * @brief Checks that the gate file has the expected content
         * This method will retrieve the @ref token_id with @ref get_id, then derive the correct @ref gate_token_key
         * from @ref gate_config::base_key using @ref gate_base_key::derive_token_key, encrypt the identity
         * for the given @p g, and then read the encrypted content through @ref read_gate_file, and compare the final
         * content with the expect data.
         * In case of encryption failure, @ref desfire::error::crypto_error is returned.
         * @see check_gate_file
         * @param km Keymaker.
         * @param g Public gate configuration.
         * @param id Identity to check.
         * @param check_app If true, it will call @ref check_gate_app on @ref gate_id::app and in case of failure, it will return
         *  @ref desfire::error::app_integrity_error.
         * @param check_file If true, it will call @ref check_gate_file on @ref gate_id::file and in case of failure, it will return
         *  @ref desfire::error::file_integrity_error.
         *  @return The token id that was used to generate keys, and
         *  - true if the file exists, is readable and the expected content
         *  - false if the file exists, is readable but the content does not match, or
         *  - @ref desfire::error::app_integrity_error If the app has incorrect settings.
         *  - @ref desfire::error::file_integrity_error If the file has incorrect settings.
         *  - @ref desfire::error::permission_denied If the derived key does not open the file.
         *  - @ref desfire::error::app_not_found If the app was not found
         *  - @ref desfire::error::file_not_found If the file was not found
         *  - @ref desfire::error::crypto_error If it was not possible to encrypt @p id
         *  - Any other @ref desfire::error in case of communication failure.
         */
        [[nodiscard]] r<bool, token_id> check_encrypted_gate_file(keymaker const &km, gate_config const &g, identity const &id, bool check_app, bool check_file) const;

        /**
         * @brief Checks that @p g is enrolled correctly.
         * This method will retrieve the @ref token_id with @ref get_id, then derive the correct @ref gate_token_key
         * from @ref gate_config::base_key using @ref gate_base_key::derive_token_key, as well as @ref gate_app_master_key
         * using @ref sec_key::derive_gate_app_master_key, then read the master file via @ref read_encrypted_master_file,
         * encrypt the identity for the given @p g, and then read the raw content through @ref read_gate_file, and compare the final
         * content with the expect data.
         * Essentially, this is @ref read_encrypted_master_file combined with @ref check_encrypted_gate_file.
         *  @return The token id that was used to generate keys, and
         *  - true if the gate file exists, is readable and the expected content
         *  - false if the gate file exists, is readable but the content does not match or
         *  - @ref desfire::error::app_integrity_error If the master or the gate app has incorrect settings.
         *  - @ref desfire::error::file_integrity_error If the master file the gate file has incorrect settings.
         *  - @ref desfire::error::permission_denied If the derived keys does not open the master or gate file.
         *  - @ref desfire::error::app_not_found If the master or gate app was not found
         *  - @ref desfire::error::file_not_found If the master file or gate file was not found
         *  - @ref desfire::error::crypto_error If it was not possible to decrypt the master identity or encrypt it for @p g
         *  - @ref desfire::error::malformed If it was not possible to parse the identity.
         *  - Any other @ref desfire::error in case of communication failure.
         */
        [[nodiscard]] r<bool, token_id> is_gate_enrolled_correctly(keymaker const &km, gate_config const &g) const;

        /**
         * @brief Performs @ref check_root and @ref read_encrypted_master_file.
         * This method will retrieve the @ref token_id with @ref get_id, then derive @ref token_root_key and @ref gate_app_master_key,
         * use those to perform @ref check_root and then attempt to read @ref read_encrypted_master_file. The app and file are
         * checked for the correct settings.
         * @return The token id that was used to generate keys, or
         *  - @ref desfire::error::permission_denied if the root key is incorrect or the gate app master key is incorrect
         *  - @ref desfire::error::picc_integrity_error if the root settings are incorrect
         *  - @ref desfire::error::app_integrity_error If the master app has incorrect settings.
         *  - @ref desfire::error::file_integrity_error If the master file has incorrect settings.
         *  - @ref desfire::error::app_not_found If the master app was not found
         *  - @ref desfire::error::file_not_found If the master file was not found
         *  - @ref desfire::error::crypto_error If it was not possible to decrypt the identity.
         *  - @ref desfire::error::malformed If it was not possible to parse the identity.
         *  - Any other @ref desfire::error in case of communication failure.
         */
        [[nodiscard]] r<token_id> is_deployed_correctly(keymaker const &km) const;


        /**
         * @brief Format the card, install the correct root settings, root key, create the master app and master file.
         * This is essentially a sequence of
         *  - @ref setup_root
         *  - @ref create_app
         *  - @ref write_encrypted_master_file
         * @warning This will format the picc!
         * @return The token id that was used to generate keys, or
         *  - @ref desfire::error::permission_denied if it was not possible to authenticate with any root key
         *  - @ref desfire::error::crypto_error If it was not possible to encrypt the identity.
         *  - Any other @ref desfire::error in case of communication failure.
         */
        r<token_id> deploy(keymaker const &km, identity const &id);

        /**
         * @brief Format the card, install the correct root settings, root key, create the master app and master file.
         * This is essentially a sequence of
         *  - @ref setup_root
         *  - @ref create_app
         *  - @ref write_encrypted_master_file
         * @warning This will format the picc!
         * @return The token id that was used to generate keys, or
         *  - @ref desfire::error::permission_denied if it was not possible to authenticate with any root key
         *  - @ref desfire::error::crypto_error If it was not possible to encrypt the identity.
         *  - Any other @ref desfire::error in case of communication failure.
         */
        r<token_id> deploy(keymaker const &km, identity const &id, desfire::any_key const &previous_rkey);

        /**
         * @brief Enrolls a gate by setting up the appropriate app, key and file.
         * This method performs the following sequence of operations:
         *   1. @ref read_encrypted_master_file is called, with app checks and file checks on.
         *      If the obtained identity does not match @p id, @ref desfire::error::parameter_error is returned.
         *   2. The gate app for @p g is created, if it does not exist. If it exists, it is checked via @ref check_gate_app/
         *      This is done via @ref ensure_gate_app.
         *   3. The gate token key is derived from @ref gate_config::app_base_key via @ref gate_base_key::derive_token_key.
         *   4. The @ref gate_token_key is enrolled via @ref enroll_gate_key.
         *   5. The encrypted file is created with @ref write_encrypted_gate_file.
         * @param km Keymaker.
         * @param g Public gate configuration.
         * @param id Identity to enroll.
         * @return The token id that was used to generate keys, or
         *  - @ref desfire::error::app_integrity_error If the master app has incorrect settings or the gate app exists already and
         *      has incorrect settings.
         *  - @ref desfire::error::file_integrity_error If the master file has incorrect settings.
         *  - @ref desfire::error::permission_denied If @ref token_root_key, @ref gate_app_master_key do not open the corresponding apps.
         *  - @ref desfire::error::app_not_found If the master app was not found
         *  - @ref desfire::error::file_not_found If the master file was not found
         *  - @ref desfire::error::crypto_error If it was not possible to decrypt the master identity or encrypt the gate's identity.
         *  - @ref desfire::error::malformed If it was not possible to parse the master identity.
         *  - @ref desfire::error::parameter_error if @p id is different from the master identity.
         *  - Any other @ref desfire::error in case of communication failure.
         */
        r<token_id> enroll_gate(keymaker const &km, gate_config const &g, identity const &id);

        /**
         * @}
         */

        [[nodiscard]] inline desfire::tag &tag() const;


        [[nodiscard]] static const char *describe(desfire::error e);
        [[nodiscard]] static bool has_custom_meaning(desfire::error e);
    };

}// namespace ka

namespace std {
    template <>
    struct iterator_traits<desfire::app_id> {
        using iterator_category = random_access_iterator_tag;
        using value_type = desfire::app_id;
        using difference_type = std::int32_t;
        using pointer = desfire::app_id;
        using reference_wrapper = desfire::app_id;
    };
}
namespace ka {

    desfire::tag &member_token::tag() const {
        return *_tag;
    }

}// namespace ka

#endif//KEYCARDACCESS_MEMBER_TOKEN_HPP
