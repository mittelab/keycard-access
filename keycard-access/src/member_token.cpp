//
// Created by spak on 9/29/22.
//

#include "member_token.hpp"
#include <desfire/esp32/crypto_impl.hpp>
#include <desfire/kdf.hpp>
#include <mlab/bin_data.hpp>

#define REQ_CMD_NAMED_RES(CMD, RNAME)                                                 \
    if (const auto RNAME = (CMD); not RNAME) {                                        \
        ESP_LOGW("KA", "Failed " #CMD " with %s", desfire::to_string(RNAME.error())); \
        return RNAME.error();                                                         \
    }

#define REQ_CMD(CMD) REQ_CMD_NAMED_RES(CMD, _r)
#define REQ_CMD_RES(CMD) REQ_CMD_NAMED_RES(CMD, r) else

namespace ka {
    member_token::member_token(desfire::tag &tag) : _tag{&tag}, _root_key{desfire::key<desfire::cipher_type::des>{}} {}

    member_token::r<member_token::id_t> member_token::id() const {
        return tag().get_card_uid();
    }

    member_token::r<> member_token::try_set_root_key(desfire::any_key k) {
        REQ_CMD(unlock_root_app(k))
        set_root_key(std::move(k));
        return mlab::result_success;
    }

    member_token::r<> member_token::unlock_root_app() const {
        return unlock_root_app(root_key());
    }

    member_token::r<> member_token::provision(config const &cfg) {
        REQ_CMD(unlock_root_app())
        REQ_CMD(tag().format_picc())
        // Set the default key
        set_root_key(desfire::key<desfire::cipher_type::des>{});
        REQ_CMD(unlock_root_app())
        // Try retrieveing the id
        REQ_CMD_RES(id()) {
            // Get the root key and set it
            auto k = get_default_root_key(*r, cfg);
            REQ_CMD(tag().change_key(k))
            return try_set_root_key(k);
        }
    }

    member_token::r<> member_token::unlock_root_app(const desfire::any_key &k) const {
        REQ_CMD(tag().select_application(desfire::root_app))
        REQ_CMD(tag().authenticate(k))
        return mlab::result_success;
    }

    key_t member_token::get_default_root_key(member_token::id_t token_id, config const &cfg) {
        desfire::esp32::default_cipher_provider provider{};
        // Construct an uint8_t view over the string by casting pointers. This is accepted by bin_data
        const mlab::range<std::uint8_t const *> salt_view{
                reinterpret_cast<std::uint8_t const *>(cfg.differentiation_salt.c_str()),
                reinterpret_cast<std::uint8_t const *>(cfg.differentiation_salt.c_str() + cfg.differentiation_salt.size())};
        // Collect the differentiation data
        desfire::bin_data input_data;
        input_data << token_id << salt_view;
        return desfire::kdf_an10922(cfg.master_key, provider, input_data);
    }
}// namespace ka