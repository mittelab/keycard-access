//
// Created by spak on 9/29/22.
//

#include <desfire/esp32/utils.hpp>
#include <desfire/kdf.hpp>
#include <ka/desfire_fs.hpp>
#include <ka/member_token.hpp>
#include <ka/ticket.hpp>
#include <sodium/randombytes.h>

namespace ka {
    member_token::member_token(desfire::tag &tag) : _tag{&tag}, _root_key{desfire::key<desfire::cipher_type::des>{}} {}

    r<token_id> member_token::id() const {
        TRY(unlock_root())
        return tag().get_card_uid();
    }

    r<> member_token::unlock_root() const {
        return desfire::fs::login_app(tag(), desfire::root_app, _root_key);
    }

    r<> member_token::try_set_root_key(token_root_key const &k) {
        TRY(tag().select_application(desfire::root_app))
        // Can I enter with the current root key?
        desfire::esp32::suppress_log suppress{DESFIRE_LOG_PREFIX};
        if (tag().authenticate(_root_key)) {
            suppress.restore();
            TRY(tag().change_key(k))
        }
        suppress.restore();
        // Can I enter with the key that was supplied?
        TRY(tag().authenticate(k))
        _root_key = k;
        return mlab::result_success;
    }

    r<> member_token::setup_root(token_root_key const &tkey) {
        TRY(unlock_root())
        TRY_RESULT(try_set_root_key(tkey)) {
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
        return mlab::result_success;
    }

    r<gate_status> member_token::get_gate_status(gate_id gid) const {
        TRY(unlock_root())
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


    r<> member_token::install_ticket(desfire::app_id aid, desfire::file_id fid, app_master_key const &mkey, ticket const &t) {
        // Do not allow any change, only create/delete file with authentication.
        // Important: we allow to change only the same key_type, otherwise the master can change access to the enrollment file
        const desfire::key_rights key_rights{desfire::same_key, false, true, false, false};
        // Retrieve the holder data that we will write in the enroll file
        TRY_RESULT(get_identity()) {
            TRY(unlock_root())
            // Create an app, allow one extra key_type
            TRY(desfire::fs::delete_app_if_exists(tag(), aid))
            TRY(desfire::fs::create_app(tag(), aid, mkey, key_rights, 1))
            // Install the ticket
            TRY(t.install(tag(), fid, r->concat()))
            // Make sure you're back on the gate master key_type
            TRY(tag().authenticate(mkey.with_key_number(0)))
        }
        return mlab::result_success;
    }

    r<identity, bool> member_token::verify_ticket(desfire::app_id aid, desfire::file_id fid, ticket const &t) const {
        TRY_RESULT(get_identity()) {
            TRY(desfire::fs::login_app(tag(), aid, t.key()))
            return std::pair<identity, bool>{std::move(*r), t.verify(tag(), fid, r->concat())};
        }
    }

    r<ticket> member_token::install_enroll_ticket(gate_id gid, gate_app_master_key const &gkey) {
        const ticket t = ticket::generate();
        TRY(install_ticket(gate::id_to_app_id(gid), gate_enroll_file, gkey, t))
        return t;
    }

    r<bool> member_token::verify_enroll_ticket(gate_id gid, ticket const &t) const {
        TRY_RESULT(verify_ticket(gate::id_to_app_id(gid), gate_enroll_file, t)) {
            return r->second;
        }
    }

    r<> member_token::install_auth_ticket(gate_id gid, gate_app_master_key const &gkey, ticket const &t) {
        return install_ticket(gate::id_to_app_id(gid), gate_authentication_file, gkey, t);
    }

    r<bool> member_token::verify_auth_ticket(gate_id gid, ticket const &t) const {
        TRY_RESULT(verify_ticket(gate::id_to_app_id(gid), gate_authentication_file, t)) {
            return r->second;
        }
    }

    r<identity> member_token::authenticate(gate_id gid, ticket const &t) const {
        // Fast-lane!
        TRY_RESULT(verify_ticket(gate::id_to_app_id(gid), gate_authentication_file, t)) {
            if (r->second) {
                return r->first;
            }
            return desfire::error::authentication_error;
        }
    }

    r<> member_token::setup_mad(identity const &id) {
        // Copy the strings into a bin_data
        const auto bin_holder = mlab::data_from_string(id.holder);
        const auto bin_publisher = mlab::data_from_string(id.publisher);
        TRY(unlock_root())
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
        TRY(unlock_root())
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