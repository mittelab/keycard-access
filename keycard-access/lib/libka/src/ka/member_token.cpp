//
// Created by spak on 9/29/22.
//

#include <ka/member_token.hpp>
#include <desfire/esp32/crypto_impl.hpp>
#include <desfire/kdf.hpp>
#include <mlab/bin_data.hpp>
#include <algorithm>
#include <esp_random.h>
#include <numeric>

#define REQ_CMD_NAMED_RES(CMD, RNAME)                                                 \
    if (const auto RNAME = (CMD); not RNAME) {                                        \
        ESP_LOGW("KA", "Failed " #CMD " with %s", desfire::to_string(RNAME.error())); \
        return RNAME.error();                                                         \
    }

#define REQ_CMD(CMD) REQ_CMD_NAMED_RES(CMD, _r)
#define REQ_CMD_RES(CMD)      \
    REQ_CMD_NAMED_RES(CMD, r) \
    else

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

    member_token::r<> member_token::try_set_root_key(desfire::any_key k) {
        REQ_CMD(tag().select_application(desfire::root_app))
        REQ_CMD(tag().authenticate(k))
        set_root_key(std::move(k));
        return mlab::result_success;
    }

    member_token::r<> member_token::setup_root_key(config const &cfg) {
        static constexpr desfire::key_rights root_app_rights{
                .allowed_to_change_keys{/* unused for PICC */},
                .master_key_changeable = true,
                .dir_access_without_auth = true,
                .create_delete_without_auth = false,
                .config_changeable = false};
        // Try retrieveing the id
        REQ_CMD_RES(id()) {
            // Use the id to compute the key
            auto k = get_default_root_key(*r, cfg);
            REQ_CMD(tag().change_key(k))
            REQ_CMD(tag().change_app_settings(root_app_rights))
        }
        return mlab::result_success;
    }

    member_token::r<> member_token::setup_mad(std::string const &holder, std::string const &publisher) {
        // Copy the strings into a bin_data
        const auto bin_holder = mlab::from_string(holder);
        const auto bin_publisher = mlab::from_string(publisher);
        // Attempt to delete the existing app
        REQ_CMD(tagfs::delete_app_if_exists(tag(), mad_aid))
        // The initial settings allow for changing the key
        const desfire::app_settings initial_mad_settings{
                desfire::app_crypto::aes_128,
                desfire::key_rights{desfire::same_key, true, true, false, true},
                1};
        REQ_CMD(tag().create_application(mad_aid, initial_mad_settings))
        // Prepare an app with a random key
        REQ_CMD_RES(tagfs::create_app_for_ro(tag(), mad_aid)) {
            // Create file for MAD version 3
            REQ_CMD(tagfs::create_ro_plain_value_file(tag(), mad_file_version, 0x3))
            // Create files with holder and publisher
            REQ_CMD(tagfs::create_ro_plain_data_file(tag(), mad_file_card_holder, bin_holder))
            REQ_CMD(tagfs::create_ro_plain_data_file(tag(), mad_file_card_publisher, bin_publisher))
            // Turn the app into read-only, discard the temporary key
            REQ_CMD(tagfs::make_app_ro(tag(), false))
        }
        return mlab::result_success;
    }

    key_t member_token::get_default_root_key(member_token::id_t token_id, config const &cfg) {
        desfire::esp32::default_cipher_provider provider{};
        // Collect the differentiation data
        desfire::bin_data input_data;
        input_data << token_id << cfg.differentiation_salt;
        return desfire::kdf_an10922(cfg.master_key, provider, input_data);
    }


    member_token::r<std::string> member_token::get_holder() const {
        REQ_CMD(tag().select_application(mad_aid))
        REQ_CMD_RES(tag().read_data(mad_file_card_holder, 0, 0xffffff, desfire::file_security::none)) {
            return mlab::to_string(*r);
        }
    }

    member_token::r<std::string> member_token::get_publisher() const {
        REQ_CMD(tag().select_application(mad_aid))
        REQ_CMD_RES(tag().read_data(mad_file_card_publisher, 0, 0xffffff, desfire::file_security::none)) {
            return mlab::to_string(*r);
        }
    }

    member_token::r<unsigned> member_token::get_mad_version() const {
        REQ_CMD(tag().select_application(mad_aid))
        REQ_CMD_RES(tag().get_value(mad_file_version, desfire::file_security::none)) {
            return unsigned(*r);
        }
    }


    member_token::r<std::vector<gate::id_t>> member_token::get_enrolled_gates() const {
        REQ_CMD(tag().select_application(desfire::root_app))
        REQ_CMD_RES(tag().get_application_ids()) {
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

    namespace tagfs {
        r<> create_ro_plain_value_file(desfire::tag &tag, desfire::file_id fid, std::int32_t value) {
            // A value file can be directly created with no write access, because it takes an initial value
            const desfire::file_settings<desfire::file_type::value> ro_settings{
                    desfire::generic_file_settings{
                            desfire::file_security::none,
                            desfire::access_rights{desfire::no_key, desfire::no_key, desfire::all_keys, desfire::no_key}},
                    desfire::value_file_settings{value, value, value, false}};
            return tag.create_file(fid, ro_settings);
        }

        r<> create_ro_plain_data_file(desfire::tag &tag, desfire::file_id fid, mlab::bin_data const &value) {
            // A data file must be created with write access, because we have to write on it before locking it.
            const desfire::file_settings<desfire::file_type::standard> init_settings{
                    desfire::generic_file_settings{
                            desfire::file_security::none,
                            desfire::access_rights{desfire::no_key, desfire::no_key, desfire::all_keys, tag.active_key_no()}},
                    desfire::data_file_settings{value.size()}};
            // Final access rights revoke the write access
            const desfire::generic_file_settings final_settings{
                    desfire::file_security::none,
                    desfire::access_rights{desfire::no_key, desfire::no_key, desfire::all_keys, desfire::no_key}};
            REQ_CMD(tag.create_file(fid, init_settings))
            REQ_CMD(tag.write_data(fid, 0, value, desfire::file_security::none))
            REQ_CMD(tag.change_file_settings(fid, final_settings, desfire::file_security::none))
            return mlab::result_success;
        }

        r<key_t> create_app_for_ro(desfire::tag &tag, desfire::app_id aid) {
            // Create a random key
            key_t k{};
            esp_fill_random(std::begin(k.k), k.k.size());
            // Settings for an app with one key that can change keys
            const desfire::app_settings initial_ro_settings{
                    desfire::app_crypto::aes_128,
                    desfire::key_rights{desfire::same_key, true, true, false, true},
                    1};
            REQ_CMD(tag.create_application(aid, initial_ro_settings))
            // Enter the application with the default key, then immediately change it to something random
            REQ_CMD(tag.select_application(aid))
            REQ_CMD(tag.authenticate(key_t{}))
            REQ_CMD(tag.change_key(k))
            REQ_CMD(tag.authenticate(k))
            return k;
        }

        r<> make_app_ro(desfire::tag &tag, bool list_requires_auth) {
            const desfire::key_rights ro_rights{
                    desfire::no_key, false, list_requires_auth, false, false};
            REQ_CMD(tag.change_app_settings(ro_rights))
            return mlab::result_success;
        }

        r<bool> does_file_exist(desfire::tag &tag, desfire::file_id fid) {
            REQ_CMD_RES(tag.get_file_ids()) {
                return std::find(std::begin(*r), std::end(*r), fid) != std::end(*r);
            }
        }

        r<bool> does_app_exist(desfire::tag &tag, desfire::app_id aid) {
            REQ_CMD_RES(tag.get_application_ids()) {
                return std::find(std::begin(*r), std::end(*r), aid) != std::end(*r);
            }
        }

        r<> delete_file_if_exists(desfire::tag &tag, desfire::file_id fid) {
            REQ_CMD_RES(does_file_exist(tag, fid)) {
                if (*r) {
                    REQ_CMD(tag.delete_file(fid))
                }
            }
            return mlab::result_success;
        }

        r<> delete_app_if_exists(desfire::tag &tag, desfire::app_id aid) {
            REQ_CMD_RES(does_app_exist(tag, aid)) {
                if (*r) {
                    REQ_CMD(tag.delete_application(aid))
                }
            }
            return mlab::result_success;
        }
    }// namespace tagfs
}// namespace ka