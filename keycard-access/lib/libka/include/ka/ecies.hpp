//
// Created by spak on 10/23/22.
//

#ifndef KEYCARDACCESS_ECIES_HPP
#define KEYCARDACCESS_ECIES_HPP

#include <ka/helpers.hpp>
#include <mlab/bin_data.hpp>

namespace ka::ecies {
    [[nodiscard]] mbedtls_result<mlab::bin_data> decrypt(mbedtls_ecp_keypair const &prvkey, mlab::bin_data const &enc_message);
    [[nodiscard]] mbedtls_result<mlab::bin_data> encrypt(mbedtls_ecp_keypair const &pubkey, mlab::bin_data const &plaintext);

    [[nodiscard]] mbedtls_result<std::array<std::uint8_t, 32>> derive_symmetric_key(std::array<std::uint8_t, 32> const &salt, mbedtls_mpi const &secret);
    [[nodiscard]] mbedtls_result<> derive_symmetric_key(std::array<std::uint8_t, 32> const &salt, mbedtls_mpi const &secret, mbedtls_gcm_context &context);
}// namespace ka::ecies

#endif//KEYCARDACCESS_ECIES_HPP
