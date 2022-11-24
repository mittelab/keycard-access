//
// Created by spak on 9/29/22.
//

#include <algorithm>
#include <desfire/esp32/crypto_impl.hpp>
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

    member_token::r<> member_token::try_set_root_key(desfire::any_key k) {
        TRY(tag().select_application(desfire::root_app))
        TRY(tag().authenticate(k))
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
        TRY_RESULT(id()) {
            // Use the id to compute the key
            auto k = get_default_root_key(*r, cfg);
            TRY(tag().change_key(k))
            TRY(tag().change_app_settings(root_app_rights))
        }
        return mlab::result_success;
    }

    member_token::r<bool> member_token::is_enrolled(gate::id_t gid) const {
        return desfire::fs::does_app_exist(tag(), gate::id_to_app_id(gid));
    }

    enroll_ticket enroll_ticket::generate() {
        enroll_ticket ticket{};
        ticket._key.randomize(randombytes_buf);
        randombytes_buf(ticket._nonce.data(), ticket._nonce.size());
        return ticket;
    }

    bool enroll_ticket::verify_enroll_file_content(mlab::bin_data const &content, const std::string &holder) const {
        const auto expected_content = get_enroll_file_content(holder);
        return expected_content.size() == content.size() and
               std::equal(std::begin(content), std::end(content), std::begin(expected_content));
    }

    mlab::bin_data enroll_ticket::get_enroll_file_content(std::string const &holder) const {
        const mlab::bin_data data = mlab::bin_data::chain(
                mlab::prealloc(nonce().size() + holder.size()),
                nonce(),
                holder);
        mlab::bin_data hash;
        hash.resize(64);
        if (0 != crypto_hash_sha512(hash.data(), data.data(), data.size())) {
            ESP_LOGE("KA", "Could not hash holder and nonce.");
            hash = {};
        }
        return hash;
    }

    std::pair<mlab::bin_data, standard_file_settings> enroll_ticket::get_enroll_file(const std::string &holder) const {
        auto data = get_enroll_file_content(holder);
        auto settings = standard_file_settings{
                desfire::generic_file_settings{
                        desfire::file_security::encrypted,
                        desfire::access_rights{key().key_number()}},
                desfire::data_file_settings{data.size()}};
        return {std::move(data), settings};
    }

    member_token::r<enroll_ticket> member_token::enroll_gate(gate::id_t gid, key_t const &gate_key) {
        const desfire::app_id aid = gate::id_to_app_id(gid);
        // Do not allow any change, only create/delete file with authentication.
        // Important: we allow to change only the same key, otherwise the master can change access to the enrollment file
        const desfire::key_rights key_rights{desfire::same_key, false, false, false, false};
        // Retrieve the holder data that we will write in the enroll file
        TRY_RESULT(get_holder()) {
            // Generate ticket and enroll file content
            const enroll_ticket ticket = enroll_ticket::generate();
            const auto [content, settings] = ticket.get_enroll_file(*r);
            // Create an app, allow one extra key
            TRY(desfire::fs::delete_app_if_exists(tag(), aid))
            TRY(desfire::fs::create_app(tag(), aid, gate_key, key_rights, 1))
            // Authenticate with the default key and change it to the specific file key
            TRY(tag().authenticate(key_t{ticket.key().key_number(), {}}))
            TRY(tag().change_key(ticket.key()))
            TRY(tag().authenticate(ticket.key()))
            // Now create the enrollment file
            TRY(tag().create_file(gate_enroll_file, settings))
            TRY(tag().write_data(gate_enroll_file, 0, content, desfire::file_security::encrypted))
            // Make sure you're back on the gate master key
            TRY(tag().authenticate(gate_key.with_key_number(0)))
            return ticket;
        }
    }

    member_token::r<bool> member_token::verify_drop_enroll_ticket(gate::id_t gid, enroll_ticket const &ticket) const {
        TRY_RESULT_AS(get_holder(), r_holder) {
            TRY(tag().select_application(gate::id_to_app_id(gid)))
            TRY(tag().authenticate(ticket.key()))
            // Read the enroll file and compare
            TRY_RESULT_AS(tag().read_data(gate_enroll_file, 0, 0xfffff, desfire::file_security::encrypted), r_read) {
                if (ticket.verify_enroll_file_content(*r_read, *r_holder)) {
                    // Delete the enroll file
                    TRY(tag().delete_file(gate_enroll_file))
                    // Reset authentication
                    TRY(tag().select_application())
                    return true;
                }
                return false;
            }
        }
    }

    member_token::r<> member_token::setup_mad(std::string const &holder, std::string const &publisher) {
        // Copy the strings into a bin_data
        const auto bin_holder = mlab::from_string(holder);
        const auto bin_publisher = mlab::from_string(publisher);
        // Attempt to delete the existing app
        TRY(desfire::fs::delete_app_if_exists(tag(), mad_aid))
        // Prepare an app with a random key
        TRY_RESULT(desfire::fs::create_app_for_ro(tag(), key_t::cipher, mad_aid, randombytes_buf)) {
            // Create file for MAD version 3
            TRY(desfire::fs::create_ro_free_plain_value_file(tag(), mad_file_version, 0x3))
            // Create files with holder and publisher
            TRY(desfire::fs::create_ro_free_plain_data_file(tag(), mad_file_card_holder, bin_holder))
            TRY(desfire::fs::create_ro_free_plain_data_file(tag(), mad_file_card_publisher, bin_publisher))
            // Turn the app into read-only, discard the temporary key
            TRY(desfire::fs::make_app_ro(tag(), false))
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
        TRY(tag().select_application(mad_aid))
        TRY_RESULT(tag().read_data(mad_file_card_holder, 0, 0xffffff, desfire::file_security::none)) {
            return mlab::to_string(*r);
        }
    }

    member_token::r<std::string> member_token::get_publisher() const {
        TRY(tag().select_application(mad_aid))
        TRY_RESULT(tag().read_data(mad_file_card_publisher, 0, 0xffffff, desfire::file_security::none)) {
            return mlab::to_string(*r);
        }
    }

    member_token::r<unsigned> member_token::get_mad_version() const {
        TRY(tag().select_application(mad_aid))
        TRY_RESULT(tag().get_value(mad_file_version, desfire::file_security::none)) {
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