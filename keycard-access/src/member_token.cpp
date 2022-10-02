//
// Created by spak on 9/29/22.
//

#include "member_token.hpp"
#include <mlab/bin_data.hpp>
#include <desfire/kdf.hpp>
#include <desfire/esp32/crypto_impl.hpp>

namespace ka {
    member_token::r<member_token::id_t> member_token::id() const {
        return tag().get_card_uid();
    }

    member_token::r<key_t> member_token::get_root_key(config const &cfg) const {
        if (const auto r = id(); r) {
            return get_root_key(*r, cfg);
        } else {
            return r.error();
        }
    }

    key_t member_token::get_root_key(member_token::id_t token_id, config const &cfg) {
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