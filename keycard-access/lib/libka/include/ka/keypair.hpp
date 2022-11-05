//
// Created by spak on 10/5/22.
//

#ifndef KEYCARDACCESS_KEYPAIR_HPP
#define KEYCARDACCESS_KEYPAIR_HPP

#include <ka/helpers.hpp>

namespace ka {

    class keypair {
        /**
         * @note Mutable because ECDSA wants non-const
         */
        mutable managed<mbedtls_ecp_keypair, &mbedtls_ecp_keypair_init, &mbedtls_ecp_keypair_free> _kp;

        [[nodiscard]] mlab::bin_data export_key_internal(bool include_private) const;

    public:
        keypair() = default;
        keypair(keypair const &) = delete;
        keypair(keypair &&) noexcept = default;
        keypair &operator=(keypair const &) = delete;
        keypair &operator=(keypair &&) noexcept = default;

        mbedtls_result<> generate();

        void clear();
        void clear_private();

        [[nodiscard]] bool has_public() const;
        [[nodiscard]] bool has_private() const;
        [[nodiscard]] bool has_matching_public_private() const;

        [[nodiscard]] mlab::bin_data export_key() const;
        [[nodiscard]] mlab::bin_data export_key(bool include_private) const;

        [[nodiscard]] mbedtls_result<> import_key(mlab::bin_data const &data);

        [[nodiscard]] mbedtls_result<mlab::bin_data> encrypt(mlab::bin_data const &data) const;
        [[nodiscard]] mbedtls_result<mlab::bin_data> decrypt(mlab::bin_data const &data) const;

        [[nodiscard]] mbedtls_result<mlab::bin_data> sign(mlab::bin_data const &data) const;
        [[nodiscard]] mbedtls_result<> verify(mlab::bin_data const &data, mlab::bin_data const &signature) const;

        [[nodiscard]] static mbedtls_result<std::array<std::uint8_t, 32>> hash(mlab::bin_data const &data);
    };
}// namespace ka

#endif//KEYCARDACCESS_KEYPAIR_HPP
