//
// Created by spak on 9/29/22.
//

#include <algorithm>
#include <desfire/esp32/cipher_provider.hpp>
#include <desfire/kdf.hpp>
#include <ka/member_token.hpp>
#include <mlab/bin_data.hpp>
#include <numeric>
#include <sodium/crypto_hash_sha512.h>
#include <sodium/randombytes.h>

#define DESFIRE_FS_LOG_PREFIX "KA"
#include <desfire/fs.hpp>

namespace mlab {
    bin_data &operator<<(bin_data &bd, std::string const &s) {
        // Construct an uint8_t view over the string by casting pointers. This is accepted by bin_data
        const mlab::range<std::uint8_t const *> view{
                reinterpret_cast<std::uint8_t const *>(s.c_str()),
                reinterpret_cast<std::uint8_t const *>(s.c_str() + s.size())};
        return bd << view;
    }

    [[nodiscard]] bin_data from_string(std::string const &s) {
        bin_data retval;
        retval << prealloc(s.size()) << s;
        return retval;
    }
    [[nodiscard]] std::string to_string(bin_data const &bd) {
        const mlab::range<char const *> view{
                reinterpret_cast<char const *>(bd.data()),
                reinterpret_cast<char const *>(bd.data() + bd.size())};
        return std::string{std::begin(view), std::end(view)};
    }
}// namespace mlab

namespace ka {
    member_token::member_token(desfire::tag &tag) : _tag{&tag}, _root_key{desfire::key<desfire::cipher_type::des>{}} {}

    member_token::r<member_token::id_t> member_token::id() const {
        return tag().get_card_uid();
    }

    member_token::r<> member_token::unlock() {
        return desfire::fs::login_app(tag(), desfire::root_app, root_key());
    }

    member_token::r<> member_token::try_set_root_key(desfire::any_key k) {
        TRY(tag().select_application(desfire::root_app))
        // Can I enter with the current root key?
        if (tag().authenticate(root_key())) {
            TRY_RESULT(tag().change_key(k)) {
                _root_key = std::move(k);
                TRY(tag().authenticate(root_key()))
            }
        } else {
            // No, can I enter with the key that was supplied?
            TRY_RESULT(tag().authenticate(k)) {
                _root_key = std::move(k);
            }
        }
        return mlab::result_success;
    }

    member_token::r<> member_token::setup_root_settings(config const &cfg) {
        TRY(unlock())
        // Try retrieveing the id
        TRY_RESULT_AS(id(), r_id) {
            // Use the id to compute the tag_key
            TRY_RESULT(try_set_root_key(get_default_root_key(*r_id, cfg))) {
                // Now verify that we have desired settings
                TRY_RESULT_AS(tag().get_app_settings(), r_settings) {
                    // If we got so far, we have at least a changeable master key. For MAD setup,
                    // we want dir_access_without_auth!
                    if (not r_settings->rights.dir_access_without_auth) {
                        if (not r_settings->rights.config_changeable) {
                            ESP_LOGW("KA", "This key has no acces w/o auth and frozen config, so I cannot setup the MAD according to spec.");
                            return desfire::error::picc_integrity_error;
                        }
                        // Change the config allowing dir access without path, and possibly no create/delete w/o auth
                        desfire::key_rights new_rights = r_settings->rights;
                        new_rights.create_delete_without_master_key = false;
                        new_rights.dir_access_without_auth = true;
                        TRY(tag().change_app_settings(new_rights))
                    } else if (r_settings->rights.create_delete_without_master_key and r_settings->rights.config_changeable) {
                        // Better not have the create/delete w/o auth
                        desfire::key_rights new_rights = r_settings->rights;
                        new_rights.create_delete_without_master_key = false;
                        TRY(tag().change_app_settings(new_rights))
                    }
                }
            }
        }
        return mlab::result_success;
    }

    member_token::r<gate_status> member_token::get_gate_status(gate::id_t gid) const {
        const auto aid = gate::id_to_app_id(gid);
        TRY_RESULT(desfire::fs::does_app_exist(tag(), aid)) {
            if (not *r) {
                return gate_status::unknown;
            }
        }
        TRY(tag().select_application(aid))
        TRY_RESULT(desfire::fs::which_files_exist(tag(), {gate_enroll_file, gate_authentication_file})) {
            gate_status retval = gate_status::unknown;
            for (desfire::file_id fid : *r) {
                switch (fid) {
                    case gate_enroll_file:
                        retval = retval | gate_status::enrolled;
                        break;
                    case gate_authentication_file:
                        retval = retval | gate_status::auth_ready;
                        break;
                    default:
                        ESP_LOGE("KA", "Unknown file in gate app.");
                        return gate_status::broken;
                }
            }
            return retval;
        }
    }

    ticket::ticket(std::uint8_t key_no) : _key{key_no, {}}, _salt{} {}

    ticket ticket::generate(std::uint8_t key_no) {
        ticket ticket{key_no};
        ticket._key.randomize(desfire::random_oracle{randombytes_buf});
        randombytes_buf(ticket._salt.data(), ticket._salt.size());
        return ticket;
    }

    bool ticket::verify_file_content(mlab::bin_data const &content, const std::string &holder) const {
        const auto expected_content = get_file_content(holder);
        return expected_content.size() == content.size() and
               std::equal(std::begin(content), std::end(content), std::begin(expected_content));
    }

    mlab::bin_data ticket::get_file_content(std::string const &text) const {
        const mlab::bin_data data = mlab::bin_data::chain(
                mlab::prealloc(salt().size() + text.size()),
                salt(),
                text);
        mlab::bin_data hash;
        hash.resize(64);
        if (0 != crypto_hash_sha512(hash.data(), data.data(), data.size())) {
            ESP_LOGE("KA", "Could not hash text and salt.");
            hash = {};
        }
        return hash;
    }

    std::pair<mlab::bin_data, standard_file_settings> ticket::get_file(const std::string &text) const {
        auto data = get_file_content(text);
        auto settings = standard_file_settings{
                desfire::file_security::encrypted,
                // Exclusive access to the required key
                desfire::access_rights{key().key_number()},
                data.size()};
        return {std::move(data), settings};
    }

    member_token::r<> member_token::check_app_for_ticket_prerequisite(const ticket &t) const {
        if (tag().active_key_no() != 0) {
            ESP_LOGE("KA", "The app is not unlocked with the master key.");
            return desfire::error::permission_denied;
        }
        // Assert that the app settings allows keys to change themselves, otherwise security is broken
        TRY_RESULT(tag().get_app_settings()) {
            if (r->rights.allowed_to_change_keys != desfire::same_key) {
                ESP_LOGE("KA", "Tickets can only be used on apps where each key can change itself.");
                return desfire::error::permission_denied;
            }
            if (r->max_num_keys <= t.key().key_number()) {
                ESP_LOGE("KA", "The app does not allow for the specified ticket key number %d", t.key().key_number());
                return desfire::error::permission_denied;
            }
        }
        return mlab::result_success;
    }

    member_token::r<> member_token::install_ticket(desfire::file_id fid, ticket const &t, std::string const &text) {
        TRY(check_app_for_ticket_prerequisite(t))
        // Create the ticket file first, so that is compatible also with apps that do not allow creating without auth
        TRY(desfire::fs::delete_file_if_exists(tag(), fid))
        const auto [content, settings] = t.get_file(text);
        TRY(tag().create_file(fid, settings))
        // Authenticate with the default tag_key and change it to the specific file tag_key
        TRY(tag().authenticate(tag_key{t.key().key_number(), {}}))
        TRY(tag().change_key(t.key()))
        TRY(tag().authenticate(t.key()))
        // Now write the content as the new key
        TRY(tag().write_data(fid, content, desfire::cipher_mode::ciphered, 0))
        // Make sure you're back on the app without authentication
        TRY(desfire::fs::logout_app(tag()))
        return mlab::result_success;
    }

    member_token::r<> member_token::write_auth_file(gate::id_t gid, tag_key const &auth_file_key, std::string const &identity) {
        TRY(tag().select_application(gate::id_to_app_id(gid)))
        // Assume the key slot is free, thus default key
        TRY(tag().authenticate(tag_key{auth_file_key.key_number(), {}}))
        TRY(tag().change_key(auth_file_key))
        TRY(desfire::fs::delete_file_if_exists(tag(), gate_authentication_file))
        const standard_file_settings auth_file_settings{
                desfire::generic_file_settings{
                        desfire::file_security::encrypted,
                        desfire::access_rights{auth_file_key.key_number()}},
                desfire::data_file_settings{identity.size()}};
        TRY(tag().create_file(gate_authentication_file, auth_file_settings))
        TRY(tag().write_data(gate_authentication_file, mlab::bin_data::chain(identity), desfire::cipher_mode::ciphered, 0))
        return mlab::result_success;
    }


    member_token::r<bool> member_token::authenticate(gate::id_t gid, tag_key const &auth_file_key, std::string const &identity) const {
        TRY_RESULT(get_gate_status(gid)) {
            if (*r != gate_status::auth_ready) {
                return false;
            }
        }
        TRY(desfire::fs::login_app(tag(), gate::id_to_app_id(gid), auth_file_key))
        TRY_RESULT(tag().read_data(gate_authentication_file, desfire::cipher_mode::ciphered, 0, identity.size())) {
            if (identity.size() != r->size()) {
                return false;
            }
            const auto identity_data_range = mlab::make_range(
                    reinterpret_cast<std::uint8_t const *>(identity.c_str()),
                    reinterpret_cast<std::uint8_t const *>(identity.c_str() + identity.size())
            );
            return std::equal(std::begin(identity_data_range), std::end(identity_data_range), std::begin(*r));
        }
    }

    member_token::r<bool> member_token::verify_ticket(desfire::file_id fid, ticket const &t, std::string const &text) const {
        TRY(check_app_for_ticket_prerequisite(t))
        // Read the enroll file and compare
        TRY(tag().authenticate(t.key()))
        TRY_RESULT_AS(tag().read_data(fid, desfire::cipher_mode::ciphered), r_read) {
            TRY(desfire::fs::logout_app(tag()))
            return t.verify_file_content(*r_read, text);
        }
    }


    member_token::r<> member_token::clear_ticket(desfire::file_id fid, const ticket &t) {
        TRY(check_app_for_ticket_prerequisite(t))
        TRY(tag().delete_file(fid))
        // Make sure the key is reset to default
        TRY(tag().authenticate(t.key()))
        TRY(tag().change_key(tag_key{t.key().key_number(), {}}))
        TRY(desfire::fs::logout_app(tag()))
        return mlab::result_success;
    }


    member_token::r<ticket> member_token::enroll_gate(gate::id_t gid, tag_key const &gate_key) {
        const desfire::app_id aid = gate::id_to_app_id(gid);
        // Do not allow any change, only create/delete file with authentication.
        // Important: we allow to change only the same tag_key, otherwise the master can change access to the enrollment file
        // TODO: Should the key right allow listing files, so that we can check the gate status without authentication?
        const desfire::key_rights key_rights{desfire::same_key, false, false, false, false};
        // Retrieve the holder data that we will write in the enroll file
        TRY_RESULT(get_holder()) {
            // Generate ticket and enroll file content
            const ticket ticket = ticket::generate();
            // Create an app, allow one extra tag_key
            TRY(desfire::fs::delete_app_if_exists(tag(), aid))
            TRY(desfire::fs::create_app(tag(), aid, gate_key, key_rights, 1))
            // Install the ticket
            TRY(install_ticket(gate_enroll_file, ticket, *r))
            // Make sure you're back on the gate master tag_key
            TRY(tag().authenticate(gate_key.with_key_number(0)))
            return ticket;
        }
    }

    member_token::r<bool> member_token::verify_enroll_ticket(gate::id_t gid, ticket const &ticket) const {
        TRY_RESULT_AS(get_holder(), r_holder) {
            TRY(desfire::fs::login_app(tag(), gate::id_to_app_id(gid), ticket.key()))
            return verify_ticket(gate_enroll_file, ticket, *r_holder);
        }
    }

    member_token::r<> member_token::setup_mad(std::string const &holder, std::string const &publisher) {
        // Copy the strings into a bin_data
        const auto bin_holder = mlab::from_string(holder);
        const auto bin_publisher = mlab::from_string(publisher);
        // Attempt to delete the existing app
        TRY(desfire::fs::delete_app_if_exists(tag(), mad_aid))
        // Prepare an app with a random tag_key
        TRY_RESULT(desfire::fs::create_app_for_ro(tag(), tag_key::cipher, mad_aid, desfire::random_oracle{randombytes_buf})) {
            // Create file for MAD version 3
            TRY(desfire::fs::create_ro_free_plain_value_file(tag(), mad_file_version, 0x3))
            // Create files with holder and publisher
            TRY(desfire::fs::create_ro_free_plain_data_file(tag(), mad_file_card_holder, bin_holder))
            TRY(desfire::fs::create_ro_free_plain_data_file(tag(), mad_file_card_publisher, bin_publisher))
            // Turn the app into read-only, discard the temporary tag_key
            TRY(desfire::fs::make_app_ro(tag(), false))
        }
        return mlab::result_success;
    }

    tag_key member_token::get_default_root_key(member_token::id_t token_id, config const &cfg) {
        desfire::esp32::default_cipher_provider provider{};
        // Collect the differentiation data
        desfire::bin_data input_data;
        input_data << token_id << cfg.differentiation_salt;
        return desfire::kdf_an10922(cfg.master_key, provider, input_data);
    }


    member_token::r<std::string> member_token::get_holder() const {
        TRY(tag().select_application(mad_aid))
        TRY_RESULT(tag().read_data(mad_file_card_holder, desfire::cipher_mode::plain)) {
            return mlab::to_string(*r);
        }
    }

    member_token::r<std::string> member_token::get_publisher() const {
        TRY(tag().select_application(mad_aid))
        TRY_RESULT(tag().read_data(mad_file_card_publisher, desfire::cipher_mode::plain)) {
            return mlab::to_string(*r);
        }
    }

    member_token::r<unsigned> member_token::get_mad_version() const {
        TRY(tag().select_application(mad_aid))
        TRY_RESULT(tag().get_value(mad_file_version, desfire::cipher_mode::plain)) {
            return unsigned(*r);
        }
    }


    member_token::r<std::vector<gate::id_t>> member_token::get_enrolled_gates() const {
        TRY(tag().select_application(desfire::root_app))
        TRY_RESULT(tag().get_application_ids()) {
            // Filter those in range
            std::vector<gate::id_t> gates;
            for (desfire::app_id const &aid : *r) {
                if (gate::is_gate_app(aid)) {
                    gates.push_back(gate::app_id_to_id(aid));
                }
            }
            return gates;
        }
    }


}// namespace ka