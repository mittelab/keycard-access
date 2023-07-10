//
// Created by spak on 9/29/22.
//

#include <desfire/bits.hpp>
#include <desfire/esp32/utils.hpp>
#include <desfire/fs.hpp>
#include <desfire/kdf.hpp>
#include <ka/gate.hpp>
#include <ka/keymaker.hpp>
#include <ka/member_token.hpp>
#include <mlab/result_macro.hpp>

#define TAG "KA"
#undef MLAB_RESULT_LOG_PREFIX
#define MLAB_RESULT_LOG_PREFIX TAG

namespace ka {
    using namespace mlab_literals;

    namespace {

        constexpr desfire::key_rights gate_app_rights{0_b, false, true, false, false};

        constexpr char boolalpha(bool b) {
            return b ? 'Y' : 'N';
        }

        r<> silent_select_application(desfire::tag &tag, desfire::app_id aid, bool expect_exists) {
            desfire::esp32::suppress_log suppress{DESFIRE_LOG_PREFIX};
            if (const auto r = tag.select_application(aid); not r) {
                if (r.error() != desfire::error::app_not_found or expect_exists) {
                    MLAB_FAIL_MSG("tag().select_application(aid)", r);
                }
                return r.error();
            }
            return mlab::result_success;
        }

        r<bool> silent_try_authenticate(desfire::tag &tag, desfire::any_key const &key) {
            desfire::esp32::suppress_log suppress{DESFIRE_LOG_PREFIX};
            if (const auto r = tag.authenticate(key); not r) {
                if (r.error() == desfire::error::permission_denied or r.error() == desfire::error::authentication_error) {
                    return false;
                }
                MLAB_FAIL_CMD("tag().authenticate(key)", r);
            }
            return true;
        }

        /**
         * @note MLAB_FAIL_CMD/MLAB_FAIL_MSG only allowed with direct tag calls
         * @note Do not suppress unless you use tag directly
         */
    }// namespace

    bool member_token::has_custom_meaning(desfire::error e) {
        return e == desfire::error::parameter_error or
               e == desfire::error::app_integrity_error or
               e == desfire::error::permission_denied or
               e == desfire::error::app_not_found or
               e == desfire::error::file_integrity_error or
               e == desfire::error::file_not_found or
               e == desfire::error::crypto_error or
               e == desfire::error::malformed or
               e == desfire::error::picc_integrity_error;
    }

    const char *member_token::describe(desfire::error e) {
        switch (e) {
            case desfire::error::parameter_error:
                return "provided identity does not match card's (or invalid app id)";
            case desfire::error::app_integrity_error:
                return "gate app has incorrect settings or permissions";
            case desfire::error::permission_denied:
                return "root key, app master key or gate key are not valid";
            case desfire::error::app_not_found:
                return "gate app does not exist";
            case desfire::error::file_integrity_error:
                return "gate or master file has incorrect settings or permissions";
            case desfire::error::file_not_found:
                return "gate or master file does not exist";
            case desfire::error::crypto_error:
                return "unable to encrypt or decrypt";
            case desfire::error::malformed:
                return "incorrect identity format";
            case desfire::error::picc_integrity_error:
                return "incorrect root settings or permissions";
            default:
                return desfire::to_string(e);
        }
    }

    member_token::member_token(desfire::tag &tag) : _tag{&tag} {}

    pn532::post_interaction member_token_responder::interact_with_tag(desfire::tag &tag) {
        member_token token{tag};
        return interact_with_token(token);
    }

    r<bool> member_token::check_key_internal(desfire::any_key const &key, desfire::app_id aid, bool expect_exists) const {
        TRY_SILENT(silent_select_application(tag(), aid, expect_exists))
        return silent_try_authenticate(tag(), key);
    }

    r<bool> member_token::check_root_key(desfire::any_key const &key) const {
        return check_key_internal(key, desfire::root_app, true);
    }


    r<bool> member_token::check_root(token_root_key const &rkey) const {
        desfire::esp32::suppress_log suppress{DESFIRE_LOG_PREFIX};
        TRY_RESULT_SILENT(check_root_key(rkey)) {
            if (not *r) {
                return desfire::error::permission_denied;
            }
        }
        if (const auto r = tag().get_app_settings(); r) {
            if (r->rights.create_delete_without_master_key or r->rights.dir_access_without_auth) {
                ESP_LOGW(TAG, "Invalid root settings: apps w/o mkey=%c, dir w/o auth=%c",
                         boolalpha(r->rights.create_delete_without_master_key),
                         boolalpha(r->rights.dir_access_without_auth));
                return false;
            }
            return true;
        } else if (r.error() == desfire::error::permission_denied or r.error() == desfire::error::authentication_error) {
            // Silent failure in this case: the permissions are not right
            return false;
        } else {
            MLAB_FAIL_CMD("tag().get_app_settings()", r);
        }
    }

    r<bool> member_token::check_gate_app(desfire::app_id aid, bool expect_exists) const {
        if (not gate_id::is_gate_app(aid)) {
            return desfire::error::parameter_error;
        }
        desfire::esp32::suppress_log suppress{DESFIRE_LOG_PREFIX};
        TRY_SILENT(silent_select_application(tag(), aid, expect_exists))
        if (const auto r = tag().get_app_settings(); r) {
            if (r->crypto != desfire::app_crypto::aes_128 or r->max_num_keys != gate_id::gates_per_app + 1) {
                ESP_LOGW(TAG, "App %02x%02x%02x, insecure settings detected: crypto=%s, max keys=%d.",
                         aid[0], aid[1], aid[2], desfire::to_string(r->crypto), r->max_num_keys);
                return false;
            }
            if (r->rights != gate_app_rights) {
                ESP_LOGW(TAG, "App %02x%02x%02x, insecure settings detected: "
                              "change mkey=%c, dir w/o auth=%c, files w/o mkey=%c, "
                              "change cfg=%c, change actor=%c.",
                         aid[0], aid[1], aid[2],
                         boolalpha(r->rights.master_key_changeable),
                         boolalpha(r->rights.dir_access_without_auth),
                         boolalpha(r->rights.create_delete_without_master_key),
                         boolalpha(r->rights.config_changeable),
                         r->rights.allowed_to_change_keys.describe());
                return false;
            }
            return true;
        } else if (r.error() == desfire::error::permission_denied or r.error() == desfire::error::authentication_error) {
            // Silent failure in this case: the permissions are not right
            return false;
        } else {
            MLAB_FAIL_CMD("tag().get_app_settings()", r);
        }
    }


    r<bool> member_token::check_gate_file_internal(desfire::file_id fid, std::uint8_t key_no, bool expect_exists) const {
        desfire::esp32::suppress_log suppress{DESFIRE_LOG_PREFIX};
        const auto aid = tag().active_app();
        if (auto r = tag().get_file_settings(fid); not r) {
            if (r.error() == desfire::error::permission_denied or r.error() == desfire::error::authentication_error) {
                // App settings are incorrect
                ESP_LOGW(TAG, "App %02x%02x%02x: does not allow public file settings retrieval.", aid[0], aid[1], aid[2]);
                return desfire::error::app_integrity_error;
            }
            if (r.error() != desfire::error::file_not_found or expect_exists) {
                MLAB_FAIL_MSG("tag().get_file_settings(fid)", r);
            }
            return r.error();
        } else {
            if (r->type() != desfire::file_type::standard) {
                ESP_LOGW(TAG, "App %02x%02x%02x, file %02x, invalid file type %s.", aid[0], aid[1], aid[2], fid, desfire::to_string(r->type()));
                return false;
            }
            const auto &gs = r->common_settings();
            if (gs.security != desfire::file_security::encrypted) {
                ESP_LOGW(TAG, "App %02x%02x%02x, file %02x, invalid security mode %s.", aid[0], aid[1], aid[2], fid, desfire::to_string(gs.security));
                return false;
            }
            if (gs.rights.read_write != desfire::no_key or gs.rights.change != desfire::no_key or gs.rights.write != desfire::no_key or
                gs.rights.read != key_no) {
                ESP_LOGW(TAG, "App %02x%02x%02x, file %02x, invalid rights: r=%c, w=%c, rw=%c, c=%c.",
                         aid[0], aid[1], aid[2], fid,
                         gs.rights.read.describe(),
                         gs.rights.write.describe(),
                         gs.rights.read_write.describe(),
                         gs.rights.change.describe());
                return false;
            }
            return true;
        }
    }


    r<bool> member_token::check_gate_file_internal(desfire::app_id aid, desfire::file_id fid, std::uint8_t key_no, bool check_app, bool expect_exists) const {
        if (not gate_id::is_gate_app(aid)) {
            return desfire::error::parameter_error;
        }
        if (check_app) {
            TRY_RESULT_SILENT(check_gate_app(aid, expect_exists)) {
                if (not *r) {
                    return desfire::error::app_integrity_error;
                }
            }
        } else {
            TRY_SILENT(silent_select_application(tag(), aid, expect_exists))
        }
        return check_gate_file_internal(fid, key_no, expect_exists);
    }


    r<bool> member_token::check_gate_file(gate_id gid, bool check_app, bool expect_exists) const {
        const auto [aid, fid] = gid.app_and_file();
        return check_gate_file_internal(aid, fid, gid.key_no(), check_app, expect_exists);
    }

    r<bool> member_token::check_master_file(bool check_app, bool expect_exists) const {
        return check_gate_file_internal(gate_id::first_aid, 0x00, 0, check_app, expect_exists);
    }


    r<bool> member_token::check_gate_key(gate_id gid, gate_token_key const &key, bool expect_exists) const {
        if (key.key_number() != gid.key_no()) {
            return desfire::error::parameter_error;
        }
        return check_key_internal(key, gid.app(), expect_exists);
    }


    r<bool> member_token::check_master_key(gate_app_master_key const &mkey, desfire::app_id aid, bool expect_exists) const {
        if (mkey.key_number() != 0 or not gate_id::is_gate_app(aid)) {
            return desfire::error::parameter_error;
        }
        return check_key_internal(mkey, aid, expect_exists);
    }


    r<mlab::bin_data> member_token::read_gate_file_internal(desfire::app_id aid, desfire::file_id fid, gate_token_key const &key, bool check_app, bool check_file) const {
        desfire::esp32::suppress_log suppress{DESFIRE_LOG_PREFIX};
        if (check_app and not check_file) {
            TRY_RESULT_SILENT(check_gate_app(aid, false)) {
                if (not *r) {
                    return desfire::error::app_integrity_error;
                }
            }
        } else if (check_file) {
            TRY_RESULT_SILENT(check_gate_file_internal(aid, fid, key.key_number(), check_app, false)) {
                if (not *r) {
                    return desfire::error::file_integrity_error;
                }
            }
        } else {
            TRY_SILENT(silent_select_application(tag(), aid, false))
        }
        TRY_RESULT_SILENT(silent_try_authenticate(tag(), key)) {
            if (not *r) {
                return desfire::error::permission_denied;
            }
        }
        if (auto r = tag().read_data(fid, desfire::comm_mode::ciphered); not r) {
            if (r.error() == desfire::error::permission_denied or r.error() == desfire::error::authentication_error or r.error() == desfire::error::crypto_error) {
                // File settings are incorrect
                ESP_LOGW(TAG, "App %02x%02x%02x, file %02x: does not allow reading with key %d.", aid[0], aid[1], aid[2], fid, key.key_number());
                return desfire::error::file_integrity_error;
            } else if (r.error() != desfire::error::file_not_found) {
                MLAB_FAIL_MSG("tag().read_data(fid, desfire::cipher_mode::ciphered)", r);
            }
            return r.error();
        } else {
            return r;
        }
    }

    r<mlab::bin_data> member_token::read_gate_file(gate_id gid, gate_token_key const &key, bool check_app, bool check_file) const {
        if (key.key_number() != gid.key_no()) {
            return desfire::error::parameter_error;
        }
        const auto [aid, fid] = gid.app_and_file();
        return read_gate_file_internal(aid, fid, key, check_app, check_file);
    }


    r<mlab::bin_data> member_token::read_master_file(gate_app_master_key const &mkey, bool check_app, bool check_file) const {
        if (mkey.key_number() != 0) {
            return desfire::error::parameter_error;
        }
        return read_gate_file_internal(gate_id::first_aid, 0x00, mkey, check_app, check_file);
    }


    r<> member_token::write_gate_file_internal(desfire::app_id aid, desfire::file_id fid, gate_app_master_key const &mkey, std::uint8_t target_key_no, mlab::bin_data const &data, bool check_app) {
        if (not gate_id::is_gate_app(aid) or mkey.key_number() != 0) {
            return desfire::error::parameter_error;
        }
        desfire::esp32::suppress_log suppress{DESFIRE_LOG_PREFIX};
        if (check_app) {
            TRY_RESULT_SILENT(check_gate_app(aid, false)) {
                if (not *r) {
                    return desfire::error::app_integrity_error;
                }
            }
        } else {
            TRY_SILENT(silent_select_application(tag(), aid, false))
        }
        TRY_RESULT_SILENT(silent_try_authenticate(tag(), mkey)) {
            if (not *r) {
                return desfire::error::permission_denied;
            }
        }
        /**
         * @note We authenticated with the master key, so the following operations should not theoretically fail.
         * Moreover, there is no custom error code that we are supposed to handle.
         */
        TRY(desfire::fs::delete_file_if_exists(tag(), fid))
        TRY(desfire::fs::create_ro_data_file(tag(), fid, data, target_key_no, desfire::file_security::encrypted))
        return mlab::result_success;
    }


    r<> member_token::write_gate_file(gate_id gid, gate_app_master_key const &mkey, mlab::bin_data const &data, bool check_app) {
        const auto [aid, fid] = gid.app_and_file();
        return write_gate_file_internal(aid, fid, mkey, gid.key_no(), data, check_app);
    }

    r<> member_token::write_master_file(gate_app_master_key const &mkey, mlab::bin_data const &data, bool check_app) {
        return write_gate_file_internal(gate_id::first_aid, 0x00, mkey, mkey.key_number(), data, check_app);
    }

    r<token_id> member_token::get_id() const {
        /**
         * @note We do not expect this command to fail at any point.
         */
        TRY_RESULT(tag().get_info()) {
            return token_id{r->serial_no};
        }
    }

    r<> member_token::create_gate_app(desfire::app_id aid, token_root_key const &rkey, gate_app_master_key const &mkey) {
        if (not gate_id::is_gate_app(aid) or mkey.key_number() != 0) {
            return desfire::error::parameter_error;
        }
        TRY_SILENT(silent_select_application(tag(), desfire::root_app, true))
        TRY_RESULT_SILENT(silent_try_authenticate(tag(), rkey)) {
            if (not *r) {
                return desfire::error::permission_denied;
            }
        }
        desfire::esp32::suppress_log suppress{DESFIRE_LOG_PREFIX};
        /**
         * @note We are authenticated with the root key, we do not expect this to fail at any point.
         */
        TRY(desfire::fs::create_app(tag(), aid, mkey, gate_app_rights, gate_id::gates_per_app))
        return mlab::result_success;
    }

    r<> member_token::enroll_gate_key(gate_id gid, gate_app_master_key const &mkey, gate_token_key const &key, bool check_app) {
        if (mkey.key_number() != 0 or key.key_number() != gid.key_no()) {
            return desfire::error::parameter_error;
        }
        const auto [aid, fid] = gid.app_and_file();
        if (check_app) {
            TRY_RESULT_SILENT(check_gate_app(aid, false)) {
                if (not *r) {
                    return desfire::error::app_integrity_error;
                }
            }
        } else {
            TRY_SILENT(silent_select_application(tag(), aid, false))
        }
        // Is the key already enrolled?
        TRY_RESULT_SILENT(silent_try_authenticate(tag(), key)) {
            if (*r) {
                return mlab::result_success;
            }
        }
        // Could only be default key
        const auto def_key = key_type{}.with_key_number(key.key_number());
        TRY_RESULT_SILENT(silent_try_authenticate(tag(), def_key)) {
            if (not *r) {
                ESP_LOGW(TAG, "App %02x%02x%02x, key %d: unable to recover previous key.", aid[0], aid[1], aid[2], key.key_number());
                return desfire::error::app_integrity_error;
            }
        }
        // We still need the master key to change it
        TRY_RESULT_SILENT(silent_try_authenticate(tag(), mkey)) {
            if (not *r) {
                return desfire::error::permission_denied;
            }
        }
        desfire::esp32::suppress_log suppress{DESFIRE_LOG_PREFIX};
        if (const auto r = tag().change_key(def_key, key); not r) {
            if (r.error() == desfire::error::permission_denied or r.error() == desfire::error::authentication_error) {
                // The app settings are incorrect because they do not allow key change
                ESP_LOGW(TAG, "App %02x%02x%02x: does not allow changing key with master key.", aid[0], aid[1], aid[2]);
                return desfire::error::app_integrity_error;
            }
            MLAB_FAIL_CMD("tag().change_key(mkey, key.key_number(), key)", r);
        }
        return mlab::result_success;
    }

    template <class Fn>
    r<> member_token::list_gate_apps_internal(bool check_app, Fn &&app_action) const {
        desfire::esp32::suppress_log suppress{DESFIRE_LOG_PREFIX};
        for (auto n_aid = gate_id::aid_range_begin; n_aid < gate_id::aid_range_end; ++n_aid) {
            const auto aid = unpack_app_id(n_aid);
            if (check_app) {
                if (const auto r = check_gate_app(aid, false); not r) {
                    if (r.error() == desfire::error::app_not_found) {
                        return mlab::result_success;
                    }
                    MLAB_FAIL_CMD("check_gate_app(aid, false)", r);
                } else if (not *r) {
                    continue;
                }
            } else {
                if (const auto r = tag().select_application(aid); not r) {
                    if (r.error() == desfire::error::app_not_found) {
                        return mlab::result_success;
                    }
                    MLAB_FAIL_CMD("tag().select_application(aid)", r);
                }
            }
            suppress.restore();
            TRY_SILENT(app_action(aid));
            suppress.suppress();
        }
        return mlab::result_success;
    }

    r<mlab::range<desfire::app_id>> member_token::list_gate_apps(bool check_app) const {
        auto last_aid = gate_id::aid_range_begin;
        TRY_SILENT(list_gate_apps_internal(check_app, [&](desfire::app_id aid) -> r<> {
            last_aid = pack_app_id(aid);
            return mlab::result_success;
        }));
        return mlab::make_range(gate_id::first_aid, unpack_app_id(last_aid + 1));
    }

    r<> member_token::ensure_gate_app(desfire::app_id aid, token_root_key const &rkey, gate_app_master_key const &mkey) {
        if (not gate_id::is_gate_app(aid) or mkey.key_number() != 0) {
            return desfire::error::parameter_error;
        }
        if (const auto r = check_gate_app(aid, false); not r) {
            if (r.error() != desfire::error::app_not_found) {
                return r.error();
            }
        } else if (*r) {
            TRY_RESULT_AS_SILENT(silent_try_authenticate(tag(), mkey), r_auth) {
                if (*r_auth) {
                    return mlab::result_success;
                } else {
                    return desfire::error::permission_denied;
                }
            }
        } else {
            return desfire::error::app_integrity_error;
        }
        return create_gate_app(aid, rkey, mkey);
    }


    r<> member_token::setup_root_internal(token_root_key const &rkey, bool format) {
        desfire::esp32::suppress_log suppress{DESFIRE_LOG_PREFIX};
        TRY_RESULT(tag().get_app_settings()) {
            auto rights = r->rights;
            rights.dir_access_without_auth = false;
            rights.create_delete_without_master_key = false;
            TRY(tag().change_app_settings(rights))
            TRY(tag().change_key(rkey))
            if (format) {
                TRY(tag().select_application())
                TRY(tag().authenticate(rkey))
                TRY(tag().format_picc())
            }
            return mlab::result_success;
        }
    }

    r<> member_token::setup_root(token_root_key const &rkey, bool format) {
        for (desfire::any_key const &k : {desfire::any_key{rkey}, desfire::any_key{desfire::cipher_type::des}}) {
            TRY_RESULT_SILENT(check_root_key(k)) {
                if (*r) {
                    return setup_root_internal(rkey, format);
                }
            }
        }
        return desfire::error::permission_denied;
    }

    r<> member_token::setup_root(token_root_key const &rkey, bool format, desfire::any_key const &previous_rkey) {
        for (desfire::any_key const &k : {previous_rkey, desfire::any_key{rkey}, desfire::any_key{desfire::cipher_type::des}}) {
            TRY_RESULT_SILENT(check_root_key(k)) {
                if (*r) {
                    return setup_root_internal(rkey, format);
                }
            }
        }
        return desfire::error::permission_denied;
    }

    r<> member_token::write_encrypted_gate_file_internal(desfire::app_id aid, desfire::file_id fid, gate_app_master_key const &mkey, std::uint8_t target_key_no, key_pair const &kp, pub_key const &pk, identity const &id, bool check_app) {
        mlab::bin_data data;
        data << id;
        if (not kp.encrypt_for(pk, data)) {
            return desfire::error::crypto_error;
        }
        return write_gate_file_internal(aid, fid, mkey, target_key_no, data, check_app);
    }

    r<token_id> member_token::write_encrypted_gate_file(keymaker const &km, gate_config const &g, identity const &id, bool check_app) {
        TRY_RESULT_AS_SILENT(get_id(), r_id) {
            const auto [aid, fid] = g.id.app_and_file();
            const auto mkey = km.keys().derive_gate_app_master_key(*r_id);
            TRY_SILENT(write_encrypted_gate_file_internal(aid, fid, mkey, g.id.key_no(), km.keys(), g.gate_pub_key, id, check_app));
            return r_id;
        }
    }

    r<token_id> member_token::write_encrypted_master_file(keymaker const &km, identity const &id, bool check_app) {
        TRY_RESULT_AS_SILENT(get_id(), r_id) {
            const auto mkey = km.keys().derive_gate_app_master_key(*r_id);
            TRY_SILENT(write_encrypted_gate_file_internal(gate_id::first_aid, 0x00, mkey, 0, km.keys(), km.keys(), id, check_app));
            return r_id;
        }
    }


    r<bool> member_token::is_enrolled_internal(desfire::app_id aid, desfire::file_id fid, std::uint8_t key_no, bool check_app, bool check_file) const {
        desfire::esp32::suppress_log suppress{DESFIRE_LOG_PREFIX};
        if (check_app and not check_file) {
            if (const auto r = check_gate_app(aid, false); r) {
                if (not *r) {
                    return desfire::error::app_integrity_error;
                }
            } else if (r.error() == desfire::error::app_not_found) {
                return false;
            } else {
                return r.error();
            }
            // Continue on, we need to test file existence
        } else if (check_file) {
            // This block always returns
            if (const auto r = check_gate_file_internal(aid, fid, key_no, check_app, false); r) {
                if (*r) {
                    return true;
                } else {
                    return desfire::error::file_integrity_error;
                }
            } else if (r.error() == desfire::error::app_not_found or r.error() == desfire::error::file_not_found) {
                return false;
            } else {
                return r.error();
            }
        } else {
            if (const auto r = silent_select_application(tag(), aid, false); not r) {
                if (r.error() == desfire::error::app_not_found) {
                    return false;
                }
                return r.error();
            }
        }
        // Try listing the files. We expect this to succeed on a correctly set up application
        if (const auto r = tag().get_file_ids(); r) {
            // Search for the one we need
            return std::find(std::begin(*r), std::end(*r), fid) != std::end(*r);
        } else if (r.error() == desfire::error::permission_denied or r.error() == desfire::error::authentication_error) {
            // Incorrectly set up app, should allow this
            ESP_LOGW(TAG, "App %02x%02x%02x: does not allow public file listing.", aid[0], aid[1], aid[2]);
            return desfire::error::app_integrity_error;
        } else {
            MLAB_FAIL_CMD("tag().get_file_ids()", r);
        }
    }

    r<bool> member_token::is_gate_enrolled(gate_id gid, bool check_app, bool check_file) const {
        const auto [aid, fid] = gid.app_and_file();
        return is_enrolled_internal(aid, fid, gid.key_no(), check_app, check_file);
    }

    r<bool> member_token::is_master_enrolled(bool check_app, bool check_file) const {
        return is_enrolled_internal(gate_id::first_aid, 0x00, 0, check_app, check_file);
    }

    r<std::vector<gate_id>> member_token::list_gates(bool check_app, bool check_file) const {
        std::vector<gate_id> gates;
        TRY_SILENT(list_gate_apps_internal(check_app, [&](desfire::app_id aid) -> r<> {
            desfire::esp32::suppress_log suppress{DESFIRE_LOG_PREFIX};
            if (const auto r = tag().get_file_ids(); r) {
                for (desfire::file_id fid : *r) {
                    if (aid == gate_id::first_aid and fid == 0x00) {
                        // Master file
                        continue;
                    }
                    if (const auto [success, gid] = gate_id::from_app_and_file(aid, fid); success) {
                        if (check_file) {
                            if (const auto r_check = check_gate_file_internal(fid, gid.key_no(), true); not r_check) {
                                if (r_check.error() == desfire::error::app_integrity_error) {
                                    // We simply move on to the next file/app
                                    continue;
                                }
                                MLAB_FAIL_CMD("check_gate_file_internal(fid, gid.key_no(), true)", r_check);
                            } else if (not *r_check) {
                                continue;
                            }
                        }
                        gates.emplace_back(gid);
                    } else {
                        ESP_LOGW(TAG, "App %02x%02x%02x: non-gate file %02x.", fid, aid[0], aid[1], aid[2]);
                    }
                }
            } else if (r.error() == desfire::error::permission_denied or r.error() == desfire::error::authentication_error) {
                // This would normally be an app integrity failure
                ESP_LOGW(TAG, "App %02x%02x%02x: does not allow public file listing.", aid[0], aid[1], aid[2]);
            } else {
                MLAB_FAIL_CMD("tag().get_file_ids()", r);
            }
            return mlab::result_success;
        }));
        return gates;
    }

    r<identity> member_token::read_encrypted_gate_file_internal(desfire::app_id aid, desfire::file_id fid, gate_token_key const &key, key_pair const &kp, pub_key const &pk, bool check_app, bool check_file) const {
        TRY_RESULT_SILENT(read_gate_file_internal(aid, fid, key, check_app, check_file)) {
            if (not kp.decrypt_from(pk, *r)) {
                return desfire::error::crypto_error;
            }
            mlab::bin_stream s{*r};
            identity id{};
            s >> id;
            if (not s.eof() or s.bad()) {
                return desfire::error::malformed;
            }
            return id;
        }
    }

    r<identity, token_id> member_token::read_encrypted_gate_file(gate const &g, bool check_app, bool check_file) const {
        TRY_RESULT_AS_SILENT(get_id(), r_id) {
            const auto [aid, fid] = g.id().app_and_file();
            /**
             * @todo Use a method of gate instead of accessing directly app_base_key
             */
            const auto key = g.derive_token_key(*r_id, g.id().key_no());
            return mlab::concat_result(read_encrypted_gate_file_internal(aid, fid, key, g.keys(), g.keymaker_pk(), check_app, check_file), r_id);
        }
    }


    r<identity, token_id> member_token::read_encrypted_master_file(keymaker const &km, bool check_app, bool check_file) const {
        TRY_RESULT_AS_SILENT(get_id(), r_id) {
            const auto mkey = km.keys().derive_gate_app_master_key(*r_id);
            return mlab::concat_result(read_encrypted_gate_file_internal(gate_id::first_aid, 0x00, mkey, km.keys(), km.keys(), check_app, check_file), r_id);
        }
    }

    [[nodiscard]] r<bool> member_token::check_encrypted_gate_file_internal(gate_token_key const &key, key_pair const &kp, gate_config const &g, identity const &id, bool check_app, bool check_file) const {
        const auto [aid, fid] = g.id.app_and_file();
        TRY_RESULT_SILENT(read_gate_file_internal(aid, fid, key, check_app, check_file)) {
            mlab::bin_data data;
            data << id;
            return kp.blind_check_ciphertext(g.gate_pub_key, data, *r);
        }
    }

    r<bool, token_id> member_token::check_encrypted_gate_file(keymaker const &km, gate_config const &g, identity const &id, bool check_app, bool check_file) const {
        TRY_RESULT_AS_SILENT(get_id(), r_id) {
            const auto key = g.app_base_key.derive_token_key(*r_id, g.id.key_no());
            return mlab::concat_result(check_encrypted_gate_file_internal(key, km.keys(), g, id, check_app, check_file), r_id);
        }
    }

    r<bool, token_id> member_token::is_gate_enrolled_correctly(keymaker const &km, gate_config const &g) const {
        TRY_RESULT_AS_SILENT(get_id(), r_id) {
            const auto [aid, fid] = g.id.app_and_file();
            const auto mkey = km.keys().derive_gate_app_master_key(*r_id);
            TRY_RESULT_AS_SILENT(read_encrypted_gate_file_internal(gate_id::first_aid, 0x00, mkey, km.keys(), km.keys(), true, true), r_exp_id) {
                const auto key = g.app_base_key.derive_token_key(*r_id, g.id.key_no());
                // The first app was already tested when reading the master file
                const bool app_needs_testing = (aid != gate_id::first_aid);
                return mlab::concat_result(check_encrypted_gate_file_internal(key, km.keys(), g, *r_exp_id, app_needs_testing, true), r_id);
            }
        }
    }


    r<token_id> member_token::enroll_gate(keymaker const &km, gate_config const &g, identity const &id) {
        TRY_RESULT_AS_SILENT(get_id(), r_id) {
            const auto [aid, fid] = g.id.app_and_file();
            const auto mkey = km.keys().derive_gate_app_master_key(*r_id);
            TRY_RESULT_SILENT(read_encrypted_gate_file_internal(gate_id::first_aid, 0x00, mkey, km.keys(), km.keys(), true, true)) {
                if (*r != id) {
                    return desfire::error::parameter_error;
                }
            }
            // At this point we have definitely tested the first app, and we know it exists
            if (aid != gate_id::first_aid) {
                const auto rkey = km.keys().derive_token_root_key(*r_id);
                TRY_SILENT(ensure_gate_app(aid, rkey, mkey))
            }
            const auto key = g.app_base_key.derive_token_key(*r_id, g.id.key_no());
            TRY_SILENT(enroll_gate_key(g.id, mkey, key, false))
            TRY_SILENT(write_encrypted_gate_file_internal(aid, fid, mkey, key.key_number(), km.keys(), g.gate_pub_key, id, false))
            return r_id;
        }
    }

    r<token_id> member_token::is_deployed_correctly(keymaker const &km) const {
        TRY_RESULT_AS_SILENT(get_id(), r_id) {
            const auto rkey = km.keys().derive_token_root_key(*r_id);
            const auto mkey = km.keys().derive_gate_app_master_key(*r_id);
            TRY_RESULT_SILENT(check_root(rkey)) {
                if (not *r) {
                    return desfire::error::picc_integrity_error;
                }
            }
            TRY_SILENT(read_encrypted_gate_file_internal(gate_id::first_aid, 0x00, mkey, km.keys(), km.keys(), true, true))
            return r_id;
        }
    }

    r<token_id> member_token::deploy(keymaker const &km, identity const &id) {
        TRY_RESULT_AS_SILENT(get_id(), r_id) {
            const auto rkey = km.keys().derive_token_root_key(*r_id);
            const auto mkey = km.keys().derive_gate_app_master_key(*r_id);
            TRY_SILENT(setup_root(rkey, true))
            TRY_SILENT(create_gate_app(gate_id::first_aid, rkey, mkey))
            TRY_SILENT(write_encrypted_gate_file_internal(gate_id::first_aid, 0x00, mkey, 0, km.keys(), km.keys(), id, false))
            return r_id;
        }
    }

    r<token_id> member_token::deploy(keymaker const &km, identity const &id, desfire::any_key const &previous_rkey) {
        TRY_RESULT_AS_SILENT(get_id(), r_id) {
            const auto rkey = km.keys().derive_token_root_key(*r_id);
            const auto mkey = km.keys().derive_gate_app_master_key(*r_id);
            TRY_SILENT(setup_root(rkey, true, previous_rkey))
            TRY_SILENT(create_gate_app(gate_id::first_aid, rkey, mkey))
            TRY_SILENT(write_encrypted_gate_file_internal(gate_id::first_aid, 0x00, mkey, 0, km.keys(), km.keys(), id, false))
            return r_id;
        }
    }

}// namespace ka