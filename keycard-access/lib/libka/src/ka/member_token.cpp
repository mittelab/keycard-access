//
// Created by spak on 9/29/22.
//

#include <desfire/esp32/utils.hpp>
#include <desfire/kdf.hpp>
#include <ka/gate.hpp>
#include <ka/desfire_fs.hpp>
#include <ka/member_token.hpp>
#include <sodium/randombytes.h>

namespace ka {

    member_token::member_token(desfire::tag &tag) : _tag{&tag}, _root_key{desfire::key<desfire::cipher_type::des>{}} {}

    pn532::post_interaction member_token_responder::interact_with_tag(desfire::tag &tag) {
        member_token token{tag};
        return interact_with_token(token);
    }

    r<token_id> member_token::get_id() const {
        TRY(tag().select_application())
        TRY_RESULT(tag().get_info()) {
            return token_id{r->serial_no};
        }
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


    r<> member_token::enroll_gate(gate_id gid, const gate_app_master_key &mkey, const identity &id) {
        TRY_RESULT(get_identity()) {
            if (*r != id) {
                ESP_LOGE("KA", "Token identity differs from expected identity!");
                return desfire::error::authentication_error;
            }
        }
        static constexpr desfire::key_rights key_rights{desfire::same_key, false, false, false, false};
        const auto aid = gate::id_to_app_id(gid);
        const auto hash_data = mlab::bin_data::chain(id.hash());
        TRY(unlock_root());
        TRY(desfire::fs::delete_app_if_exists(tag(), aid));
        TRY(desfire::fs::create_app(tag(), aid, mkey, key_rights));
        TRY(desfire::fs::login_app(tag(), aid, mkey));
        TRY(desfire::fs::create_ro_data_file(tag(), gate_authentication_file, hash_data, mkey.key_number(), desfire::file_security::encrypted));
        TRY(desfire::fs::logout_app(tag()));
        return mlab::result_success;
    }

    r<bool> member_token::is_gate_enrolled(gate_id gid) const {
        desfire::esp32::suppress_log suppress{DESFIRE_LOG_PREFIX};
        if (const auto r = tag().select_application(gate::id_to_app_id(gid)); r) {
            return true;
        } else if (r.error() == desfire::error::app_not_found) {
            return false;
        } else {
            return r.error();
        }
    }

    r<identity> member_token::authenticate(gate_id gid, const gate_app_master_key &mkey) const {
        desfire::esp32::suppress_log suppress{DESFIRE_LOG_PREFIX, DESFIRE_FS_LOG_PREFIX};
        TRY(desfire::fs::login_app(tag(), gate::id_to_app_id(gid), mkey))
        TRY_RESULT_AS(tag().read_data(gate_authentication_file, desfire::cipher_mode::ciphered), r_hash) {
            if (r_hash->size() != hash_type::array_size) {
                ESP_LOGE("KA", "Invalid authentication file length %d, should be %d.", r_hash->size(), hash_type::array_size);
                return desfire::error::length_error;
            }
            TRY_RESULT_AS(get_identity(), r_id) {
                const auto hash = r_id->hash();
                if (std::equal(std::begin(hash), std::end(hash), std::begin(*r_hash))) {
                    return r_id;
                }
                ESP_LOGE("KA", "Mismatch declared identity.");
                return desfire::error::file_integrity_error;
            }
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
            TRY(desfire::fs::create_ro_free_value_file(tag(), mad_file_version, 0x3))
            // Create files with holder and publisher
            TRY(desfire::fs::create_ro_free_data_file(tag(), mad_file_card_holder, bin_holder))
            TRY(desfire::fs::create_ro_free_data_file(tag(), mad_file_card_publisher, bin_publisher))
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
        TRY_RESULT(tag().get_info()) {
            id.id = token_id{r->serial_no};
        }
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