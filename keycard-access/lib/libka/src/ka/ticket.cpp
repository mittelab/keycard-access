//
// Created by spak on 1/8/23.
//

#include <ka/ticket.hpp>
#include <sodium/crypto_hash_sha512.h>
#include <sodium/randombytes.h>
#include <ka/desfire_fs.hpp>

namespace ka {

    ticket::ticket(std::uint8_t key_no) : _key{key_no, {}}, _salt{} {}

    ticket ticket::generate(std::uint8_t key_no) {
        ticket ticket{key_no};
        ticket._key.randomize(desfire::random_oracle{randombytes_buf});
        randombytes_buf(ticket._salt.data(), ticket._salt.size());
        return ticket;
    }

    bool ticket::verify_file_content(mlab::bin_data const &content, const std::string &text_to_verify) const {
        const auto expected_content = get_file_content(text_to_verify);
        return expected_content.size() == content.size() and
               std::equal(std::begin(content), std::end(content), std::begin(expected_content));
    }

    mlab::bin_data ticket::get_file_content(std::string const &original_text) const {
        const mlab::bin_data data = mlab::bin_data::chain(
                mlab::prealloc(salt().size() + original_text.size()),
                salt(),
                mlab::view_from_string(original_text));
        mlab::bin_data hash;
        hash.resize(64);
        if (0 != crypto_hash_sha512(hash.data(), data.data(), data.size())) {
            ESP_LOGE("KA", "Could not hash text and salt.");
            hash = {};
        }
        return hash;
    }

    std::pair<mlab::bin_data, std_file_settings> ticket::get_file(const std::string &original_text) const {
        auto data = get_file_content(original_text);
        auto settings = std_file_settings{
                desfire::file_security::encrypted,
                // Exclusive access to the required key
                desfire::access_rights{key().key_number()},
                data.size()};
        return {std::move(data), settings};
    }

    r<> ticket::install(desfire::tag &tag, desfire::file_id fid, std::string const &original_text) const {
        TRY(check_app_for_prerequisites(tag))
        // Create the ticket file first, so that is compatible also with apps that do not allow creating without auth
        TRY(desfire::fs::delete_file_if_exists(tag, fid))
        const auto [content, settings] = get_file(original_text);
        TRY(tag.create_file(fid, settings))
        // Authenticate with the default key_type and change it to the specific file key_type
        TRY(tag.authenticate(key_type{key().key_number(), {}}))
        TRY(tag.change_key(key()))
        TRY(tag.authenticate(key()))
        // Now write the content as the new key
        TRY(tag.write_data(fid, content, desfire::cipher_mode::ciphered, 0))
        // Make sure you're back on the app without authentication
        TRY(desfire::fs::logout_app(tag))
        return mlab::result_success;
    }

    r<bool> ticket::verify(desfire::tag &tag, desfire::file_id fid, std::string const &text_to_verify) const {
        // Read the enroll file and compare
        TRY(tag.authenticate(key()))
        TRY_RESULT_AS(tag.read_data(fid, desfire::cipher_mode::ciphered), r_read) {
            TRY(desfire::fs::logout_app(tag))
            return verify_file_content(*r_read, text_to_verify);
        }
    }


    r<> ticket::clear(desfire::tag &tag, desfire::file_id fid) const {
        TRY(check_app_for_prerequisites(tag))
        TRY(tag.delete_file(fid))
        // Make sure the key is reset to default
        TRY(tag.authenticate(key()))
        TRY(tag.change_key(key_type{key().key_number(), {}}))
        TRY(desfire::fs::logout_app(tag))
        return mlab::result_success;
    }


    r<> ticket::check_app_for_prerequisites(desfire::tag &tag) const {
        if (tag.active_key_no() != 0) {
            ESP_LOGE("KA", "The app is not unlocked with the master key.");
            return desfire::error::permission_denied;
        }
        // Assert that the app settings allows keys to change themselves, otherwise security is broken
        TRY_RESULT(tag.get_app_settings()) {
            if (r->rights.allowed_to_change_keys != desfire::same_key) {
                ESP_LOGE("KA", "Tickets can only be used on apps where each key can change itself.");
                return desfire::error::permission_denied;
            }
            if (r->max_num_keys <= key().key_number()) {
                ESP_LOGE("KA", "The app does not allow for the specified ticket key number %d", key().key_number());
                return desfire::error::permission_denied;
            }
        }
        return mlab::result_success;
    }

}