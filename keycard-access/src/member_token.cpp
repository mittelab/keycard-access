//
// Created by spak on 9/29/22.
//

#include "member_token.hpp"
#include <mlab/bin_data.hpp>
#include <desfire/kdf.hpp>
#include <desfire/esp32/crypto_impl.hpp>

namespace ka {
    member_token::member_token(desfire::tag &tag) : _tag{&tag}, _root_key{desfire::key<desfire::cipher_type::des>{}} {}

    member_token::r<member_token::id_t> member_token::id() const {
        return tag().get_card_uid();
    }

    member_token::r<> member_token::try_set_root_key(desfire::any_key k) {
        if (const auto r = tag().select_application(desfire::root_app); not r) {
            return r.error();
        }
        if (const auto r = tag().authenticate(k); not r) {
            return r.error();
        }
        set_root_key(std::move(k));
        return mlab::result_success;
    }

    member_token::r<> member_token::test_root_key() const {
        return test_root_key(root_key());
    }

    member_token::r<> member_token::test_root_key(const desfire::any_key &k) const {
        if (const auto r = tag().select_application(desfire::root_app); not r) {
            return r.error();
        }
        return tag().authenticate(k);
    }

    key_t member_token::get_default_root_key(member_token::id_t token_id, config const &cfg) {
        desfire::esp32::default_cipher_provider provider{};
        // Construct an uint8_t view over the string by casting pointers. This is accepted by bin_data
        const mlab::range<std::uint8_t const *> salt_view{
            reinterpret_cast<std::uint8_t const *>(cfg.differentiation_salt.c_str()),
            reinterpret_cast<std::uint8_t const *>(cfg.differentiation_salt.c_str() + cfg.differentiation_salt.size())
        };
        // Collect the differentiation data
        desfire::bin_data input_data;
        input_data << token_id << salt_view;
        return desfire::kdf_an10922(cfg.master_key, provider, input_data);
    }
}