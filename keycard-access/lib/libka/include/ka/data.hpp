//
// Created by spak on 1/8/23.
//

#ifndef KEYCARD_ACCESS_DATA_HPP
#define KEYCARD_ACCESS_DATA_HPP

#include <desfire/data.hpp>
#include <desfire/keys.hpp>
#include <desfire/tag.hpp>

namespace ka {

    using key_type = desfire::key<desfire::cipher_type::aes128>;
    using std_file_settings = desfire::file_settings<desfire::file_type::standard>;

    template <class... Tn>
    using r = desfire::tag::result<Tn...>;

    struct identity {
        std::string holder;
        std::string publisher;
    };

    enum struct gate_status : std::uint8_t {
        unknown = 0b00,
        enrolled = 0b01,
        auth_ready = 0b10,
        broken = enrolled | auth_ready
    };

    struct app_master_key : public key_type {
        using key_type::key_type;
    };

    struct gate_key : public app_master_key {
        using app_master_key::app_master_key;
    };

    struct root_key : public key_type {
        using key_type::key_type;
    };

    [[nodiscard]] inline bool operator&(gate_status gs1, gate_status gs2);
    [[nodiscard]] inline gate_status operator|(gate_status gs1, gate_status gs2);

}// namespace ka

namespace mlab {
    [[nodiscard]] mlab::range<std::uint8_t const *> view_from_string(std::string const &s);
    [[nodiscard]] bin_data data_from_string(std::string const &s);
    [[nodiscard]] std::string data_to_string(bin_data const &bd);
}// namespace mlab

namespace ka {

    bool operator&(gate_status gs1, gate_status gs2) {
        using numeric_t = std::underlying_type_t<gate_status>;
        return (static_cast<numeric_t>(gs1) & static_cast<numeric_t>(gs2)) != 0;
    }

    gate_status operator|(gate_status gs1, gate_status gs2) {
        using numeric_t = std::underlying_type_t<gate_status>;
        return static_cast<gate_status>(static_cast<numeric_t>(gs1) | static_cast<numeric_t>(gs2));
    }

}// namespace ka
#endif//KEYCARD_ACCESS_DATA_HPP
