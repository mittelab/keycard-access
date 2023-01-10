//
// Created by spak on 9/29/22.
//

#include <desfire/kdf.hpp>
#include <ka/desfire_fs.hpp>
#include <ka/member_token.hpp>
#include <ka/ticket.hpp>
#include <sodium/randombytes.h>

namespace ka {
    member_token::member_token(desfire::tag &tag) : _tag{&tag}, _root_key{desfire::key<desfire::cipher_type::des>{}} {}

    r<token_id> member_token::id() const {
        return tag().get_card_uid();
    }

    r<> member_token::unlock() {
        return desfire::fs::login_app(tag(), desfire::root_app, _root_key);
    }

    r<> member_token::try_set_root_key(token_root_key const &k) {
        TRY(tag().select_application(desfire::root_app))
        // Can I enter with the current root key?
        // TODO suppress log
        if (tag().authenticate(_root_key)) {
            TRY(tag().change_key(k))
        }
        // Can I enter with the key that was supplied?
        TRY(tag().authenticate(k))
        _root_key = k;
        return mlab::result_success;
    }

    r<> member_token::setup_root(one_key_to_bind_them const &onekey) {
        TRY(unlock())
        // Try retrieveing the id
        TRY_RESULT_AS(id(), r_id) {
            // Use the id to compute the key_type
            TRY_RESULT(try_set_root_key(onekey.derive_token_root_key(*r_id))) {
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

    r<gate_status> member_token::get_gate_status(gate_id gid) const {
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

    r<> member_token::write_auth_file(gate_id gid, key_type const &auth_file_key, std::string const &identity) {
        TRY(tag().select_application(gate::id_to_app_id(gid)))
        // Assume the key slot is free, thus default key
        TRY(tag().authenticate(key_type{auth_file_key.key_number(), {}}))
        TRY(tag().change_key(auth_file_key))
        TRY(desfire::fs::delete_file_if_exists(tag(), gate_authentication_file))
        const std_file_settings auth_file_settings{
                desfire::generic_file_settings{
                        desfire::file_security::encrypted,
                        desfire::access_rights{auth_file_key.key_number()}},
                desfire::data_file_settings{identity.size()}};
        TRY(tag().create_file(gate_authentication_file, auth_file_settings))
        TRY(tag().write_data(gate_authentication_file, mlab::data_from_string(identity), desfire::cipher_mode::ciphered, 0))
        return mlab::result_success;
    }


    r<bool> member_token::authenticate(gate_id gid, key_type const &auth_file_key, std::string const &identity) const {
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

    r<ticket> member_token::install_enroll_ticket(gate_id gid, gate_app_master_key const &gkey) {
        const desfire::app_id aid = gate::id_to_app_id(gid);
        // Do not allow any change, only create/delete file with authentication.
        // Important: we allow to change only the same key_type, otherwise the master can change access to the enrollment file
        const desfire::key_rights key_rights{desfire::same_key, false, true, false, false};
        // Retrieve the holder data that we will write in the enroll file
        TRY_RESULT(get_identity()) {
            // Generate ticket and enroll file content
            const ticket ticket = ticket::generate();
            // Create an app, allow one extra key_type
            TRY(desfire::fs::delete_app_if_exists(tag(), aid))
            TRY(desfire::fs::create_app(tag(), aid, gkey, key_rights, 1))
            // Install the ticket
            TRY(ticket.install(tag(), gate_enroll_file, r->concat()))
            // Make sure you're back on the gate master key_type
            TRY(tag().authenticate(gkey.with_key_number(0)))
            return ticket;
        }
    }

    r<bool> member_token::verify_enroll_ticket(gate_id gid, ticket const &ticket) const {
        TRY_RESULT(get_identity()) {
            TRY(desfire::fs::login_app(tag(), gate::id_to_app_id(gid), ticket.key()))
            return ticket.verify(tag(), gate_enroll_file, r->concat());
        }
    }

    r<> member_token::setup_mad(identity const &id) {
        // Copy the strings into a bin_data
        const auto bin_holder = mlab::data_from_string(id.holder);
        const auto bin_publisher = mlab::data_from_string(id.publisher);
        // Attempt to delete the existing app
        TRY(desfire::fs::delete_app_if_exists(tag(), mad_aid))
        // Prepare an app with a random key_type
        TRY_RESULT(desfire::fs::create_app_for_ro(tag(), key_type::cipher, mad_aid, desfire::random_oracle{randombytes_buf})) {
            // Create file for MAD version 3
            TRY(desfire::fs::create_ro_free_plain_value_file(tag(), mad_file_version, 0x3))
            // Create files with holder and publisher
            TRY(desfire::fs::create_ro_free_plain_data_file(tag(), mad_file_card_holder, bin_holder))
            TRY(desfire::fs::create_ro_free_plain_data_file(tag(), mad_file_card_publisher, bin_publisher))
            // Turn the app into read-only, discard the temporary key_type
            TRY(desfire::fs::make_app_ro(tag(), false))
        }
        return mlab::result_success;
    }

    r<std::string> member_token::get_holder() const {
        TRY(tag().select_application(mad_aid))
        TRY_RESULT(tag().read_data(mad_file_card_holder, desfire::cipher_mode::plain)) {
            return mlab::data_to_string(*r);
        }
    }

    r<std::string> member_token::get_publisher() const {
        TRY(tag().select_application(mad_aid))
        TRY_RESULT(tag().read_data(mad_file_card_publisher, desfire::cipher_mode::plain)) {
            return mlab::data_to_string(*r);
        }
    }

    r<identity> member_token::get_identity() const {
        TRY(tag().select_application(mad_aid))
        identity id{};
        TRY_RESULT(tag().read_data(mad_file_card_holder, desfire::cipher_mode::plain)) {
            id.holder = mlab::data_to_string(*r);
        }
        TRY_RESULT(tag().read_data(mad_file_card_publisher, desfire::cipher_mode::plain)) {
            id.publisher = mlab::data_to_string(*r);
        }
        return id;
    }

    r<unsigned> member_token::get_mad_version() const {
        TRY(tag().select_application(mad_aid))
        TRY_RESULT(tag().get_value(mad_file_version, desfire::cipher_mode::plain)) {
            return unsigned(*r);
        }
    }


    r<std::vector<gate_id>> member_token::get_enrolled_gates() const {
        TRY(tag().select_application(desfire::root_app))
        TRY_RESULT(tag().get_application_ids()) {
            // Filter those in range
            std::vector<gate_id> gates;
            for (desfire::app_id const &aid : *r) {
                if (gate::is_gate_app(aid)) {
                    gates.push_back(gate::app_id_to_id(aid));
                }
            }
            return gates;
        }
    }


}// namespace ka