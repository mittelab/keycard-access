//
// Created by spak on 10/14/22.
//

#include <ka/ecies.hpp>
#include <ka/helpers.hpp>
#include <ka/secure_rng.hpp>
#include <mbedtls/ecdh.h>
#include <mlab/bin_data.hpp>

/**
 * @note ''esp_config.h'' must be included before ''aes.h'' to enable hardware AES.
 * @{
 */
#include <mbedtls/esp_config.h>
/**
 * @}
 */


/**
 * Guard against missing the definition of CONFIG_MBEDTLS_HKDF_C.
 */
#ifndef MBEDTLS_HKDF_C
#error "libKA: config macro CONFIG_MBEDTLS_HKDF_C not found; make sure you have CONFIG_MBEDTLS_HKDF_C=y in your sdkconfig!"
#endif

namespace ka::ecies {

    namespace {
        constexpr std::size_t salt_size = 32;
        /**
         * AES tag size is 16 bytes.
         */
        constexpr std::size_t tag_size = 16;
        /**
         * GCM recommends 12 bytes, so that the IV does not have to be rehashed into 12 bytes
         */
        constexpr std::size_t iv_size = 12;

        /**
         * Expected size taken up by the public key, used for preallocating data
         */
        constexpr std::size_t max_pubkey_size_hint = MBEDTLS_ECP_MAX_PT_LEN + 2;
    }// namespace

    mbedtls_result<mlab::bin_data> decrypt(mbedtls_ecp_keypair const &prvkey, mlab::bin_data const &enc_message) {
        // Ensure it has capabilities
        MBEDTLS_TRY(mbedtls_ecp_check_privkey(&prvkey.grp, &prvkey.d))

        // Make a copy of the elliptic curve group, we need non-const for mbedtls operation
        managed<mbedtls_ecp_group, &mbedtls_ecp_group_init, &mbedtls_ecp_group_free> grp;
        MBEDTLS_TRY(mbedtls_ecp_group_copy(grp, &prvkey.grp))

        // Data needed for decryption, in order
        std::array<std::uint8_t, iv_size> iv{};
        std::array<std::uint8_t, salt_size> salt{};
        managed<mbedtls_ecp_point, &mbedtls_ecp_point_init, &mbedtls_ecp_point_free> eph_pub;

        // Pull all the data out
        mlab::bin_stream s{enc_message};
        s >> iv >> salt >> std::make_pair(std::cref(prvkey.grp), std::ref(*eph_pub));

        const auto ciphertext = s.read(s.remaining() - tag_size);
        const auto tag = s.read(tag_size);

        // If we have not managed to read all this data, then the stream is malformed
        if (s.bad() or not s.eof()) {
            return mbedtls_err::other;
        }

        // Compute the shared secret
        managed<mbedtls_mpi, &mbedtls_mpi_init, &mbedtls_mpi_free> secret;
        MBEDTLS_TRY(mbedtls_ecdh_compute_shared(grp, secret, eph_pub, &prvkey.d, default_secure_rng().fn(), default_secure_rng().arg()))

        // Derive and set the symmetric cipher key up
        managed<mbedtls_gcm_context, &mbedtls_gcm_init, &mbedtls_gcm_free> aes_gcm;
        if (const auto r = derive_symmetric_key(salt, *secret, *aes_gcm); not r) {
            return r.error();
        }

        // Perform the actual decryption operation
        mlab::bin_data plaintext;
        plaintext.resize(ciphertext.size());
        MBEDTLS_TRY(mbedtls_gcm_auth_decrypt(aes_gcm, ciphertext.size(),
                                             iv.data(), iv.size(), nullptr, 0,
                                             tag.data(), tag.size(),
                                             ciphertext.data(), plaintext.data()))

        return plaintext;
    }

    mbedtls_result<mlab::bin_data> encrypt(mbedtls_ecp_keypair const &pubkey, mlab::bin_data const &plaintext) {
        // Ensure it has capabilities
        MBEDTLS_TRY(mbedtls_ecp_check_pubkey(&pubkey.grp, &pubkey.Q))

        // Generate an ephemeral keypair
        managed<mbedtls_ecp_keypair, &mbedtls_ecp_keypair_init, &mbedtls_ecp_keypair_free> eph_keypair;
        MBEDTLS_TRY(mbedtls_ecp_gen_key(pubkey.grp.id, eph_keypair, default_secure_rng().fn(), default_secure_rng().arg()))

        // Computed shared secret
        managed<mbedtls_mpi, &mbedtls_mpi_init, &mbedtls_mpi_free> secret;
        MBEDTLS_TRY(mbedtls_ecdh_compute_shared(&eph_keypair->grp, secret, &pubkey.Q, &eph_keypair->d, default_secure_rng().fn(), default_secure_rng().arg()))

        // Prepare salt and IV for later encryption
        std::array<std::uint8_t, salt_size> salt{};
        std::array<std::uint8_t, iv_size> iv{};
        default_secure_rng().fill(salt);
        default_secure_rng().fill(iv);

        // Derive and set the symmetric cipher key up
        managed<mbedtls_gcm_context, &mbedtls_gcm_init, &mbedtls_gcm_free> aes_gcm;
        if (const auto r = derive_symmetric_key(salt, *secret, *aes_gcm); not r) {
            return r.error();
        }
        // Prepare an output buffer; copy IV, salt, public key
        mlab::bin_data enc_message{mlab::prealloc(iv.size() + salt.size() + max_pubkey_size_hint + plaintext.size() + tag_size)};
        enc_message << iv << salt << std::make_pair(std::cref(eph_keypair->grp), std::cref(eph_keypair->Q));

        // Preallocation just allocates, now resize to the full required length so that the buffer is available for writing
        const auto ciphertext_offset = enc_message.size();
        enc_message.resize(enc_message.size() + plaintext.size() + tag_size);

        // Select the data windows for ciphertext and tag
        const auto ciphertext = mlab::make_range(
                std::begin(enc_message) + std::ptrdiff_t(ciphertext_offset),
                std::begin(enc_message) + std::ptrdiff_t(ciphertext_offset + plaintext.size()));

        const auto tag = mlab::make_range(ciphertext.end(), enc_message.end());

        assert(tag.size() == tag_size);
        assert(ciphertext.size() == std::ptrdiff_t(plaintext.size()));

        MBEDTLS_TRY(mbedtls_gcm_crypt_and_tag(aes_gcm, MBEDTLS_GCM_ENCRYPT, plaintext.size(),
                                              iv.data(), iv.size(), nullptr, 0,
                                              plaintext.data(), ciphertext.data(), tag.size(), tag.data()))
        return enc_message;
    }

    mbedtls_result<std::array<std::uint8_t, 32>> derive_symmetric_key(std::array<std::uint8_t, 32> const &salt, mbedtls_mpi const &secret) {
        // Save the secret into a fixed size buffer. 128 bytes should suffice, even with 521 bits of key
        std::array<std::uint8_t, MBEDTLS_ECP_MAX_BYTES> secret_bin{};
        MBEDTLS_TRY(mbedtls_mpi_write_binary_le(&secret, std::begin(secret_bin), secret_bin.size()))
        // Derive the key.
        std::array<std::uint8_t, 32> sym_key{};
        MBEDTLS_TRY(mbedtls_hkdf(
                mbedtls_md_info_from_type(MBEDTLS_MD_SHA512), std::begin(salt), salt.size(),
                std::begin(secret_bin), secret_bin.size(), nullptr, 0, std::begin(sym_key), sym_key.size()))
        return sym_key;
    }

    mbedtls_result<> derive_symmetric_key(std::array<std::uint8_t, 32> const &salt, mbedtls_mpi const &secret, mbedtls_gcm_context &context) {
        if (const auto r = derive_symmetric_key(salt, secret); r) {
            MBEDTLS_TRY(mbedtls_gcm_setkey(&context, MBEDTLS_CIPHER_ID_AES, r->data(), r->size()))
            return mlab::result_success;
        } else {
            return r.error();
        }
    }

}// namespace ka::ecies