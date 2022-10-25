//
// Created by spak on 10/5/22.
//

#ifndef KEYCARDACCESS_KEYPAIR_HPP
#define KEYCARDACCESS_KEYPAIR_HPP

#include <ka/helpers.hpp>

namespace ka {

    class keypair {
        managed<mbedtls_ecp_keypair, &mbedtls_ecp_keypair_init, &mbedtls_ecp_keypair_free> _kp;

        [[nodiscard]] mlab::bin_data export_key_internal(bool include_private) const;

    public:
        keypair(keypair const &) = delete;
        keypair(keypair &&) noexcept = default;
        keypair &operator=(keypair const &) = delete;
        keypair &operator=(keypair &&) noexcept = default;

        void generate();
        void clear();
        void clear_private();

        [[nodiscard]] bool has_public() const;
        [[nodiscard]] bool has_private() const;
        [[nodiscard]] bool has_matching_public_private() const;

        [[nodiscard]] mlab::bin_data export_key() const;
        [[nodiscard]] mlab::bin_data export_key(bool include_private) const;

        [[nodiscard]] bool import_key(mlab::bin_data const &data);
    };
}// namespace ka

#endif//KEYCARDACCESS_KEYPAIR_HPP
