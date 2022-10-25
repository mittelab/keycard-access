//
// Created by spak on 10/14/22.
//

#include <ka/ecies.hpp>
#include <ka/helpers.hpp>
#include <ka/secure_rng.hpp>
#include <mbedtls/ecdh.h>
#include <mlab/bin_data.hpp>

namespace ka {

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
    }// namespace

    ::size_t public_key_size(mbedtls_ecp_group const &g) {
        return mbedtls_mpi_size(&g.P) * 2 + 1;
    }

    mbedtls_result<mlab::bin_data> ecies_decrypt(mbedtls_ecp_keypair const &prvkey, mlab::bin_data const &enc_message) {
        // Ensure it has capabilities
        MBEDTLS_TRY(mbedtls_ecp_check_privkey(&prvkey.grp, &prvkey.d))

        // Make a copy of the elliptic curve group, we need non-const for mbedtls operation
        managed<mbedtls_ecp_group, &mbedtls_ecp_group_init, &mbedtls_ecp_group_free> grp;
        MBEDTLS_TRY(mbedtls_ecp_group_copy(grp, &prvkey.grp))

        // Data needed for decryption, in order
        std::array<std::uint8_t, iv_size> iv{};
        std::array<std::uint8_t, salt_size> salt{};
        const auto eph_pub_bin_len = public_key_size(prvkey.grp);
        // Make sure we can actually read all that data
        if (enc_message.size() < iv.size() + salt.size() + eph_pub_bin_len + tag_size) {
            return mbedtls_err::other;
        }
        // Pull all the data out
        mlab::bin_stream s{enc_message};
        s >> iv >> salt;
        assert(s.good());
        const auto eph_pub_bin = s.read(eph_pub_bin_len);
        assert(s.remaining() >= tag_size);
        const auto ciphertext = s.read(s.remaining() - tag_size);
        const auto tag = s.read(tag_size);
        assert(s.eof());

        // Convert the ephemeral public key into an elliptic curve point
        managed<mbedtls_ecp_point, &mbedtls_ecp_point_init, &mbedtls_ecp_point_free> eph_pub;
        MBEDTLS_TRY(mbedtls_ecp_point_read_binary(grp, eph_pub, eph_pub_bin.data(), eph_pub_bin.size()))

        // Compute the shared secret
        managed<mbedtls_mpi, &mbedtls_mpi_init, &mbedtls_mpi_free> secret;
        MBEDTLS_TRY(mbedtls_ecdh_compute_shared(grp, secret, eph_pub, &prvkey.d, default_secure_rng().fn(), default_secure_rng().arg()))

        // Derive and set the symmetric cipher key up
        managed<mbedtls_gcm_context, &mbedtls_gcm_init, &mbedtls_gcm_free> aes_gcm;
        if (const auto r = ecies_derive_symmetric_key(salt, *secret, *aes_gcm); not r) {
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

    mbedtls_result<mlab::bin_data> ecies_encrypt(mbedtls_ecp_keypair const &pubkey, mlab::bin_data const &plaintext) {
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
        if (const auto r = ecies_derive_symmetric_key(salt, *secret, *aes_gcm); not r) {
            return r.error();
        }

        // Save the public key into a binary format
        std::array<std::uint8_t, MBEDTLS_ECP_MAX_PT_LEN> eph_pub_bin{};
        std::size_t eph_pub_bin_len = 0;
        MBEDTLS_TRY(mbedtls_ecp_point_write_binary(&eph_keypair->grp, &eph_keypair->Q, MBEDTLS_ECP_PF_UNCOMPRESSED,
                                                   &eph_pub_bin_len, std::begin(eph_pub_bin), eph_pub_bin.size()))
        // Also assert that the public key has a predictable size, so we can encode it fixed-length
        if (const auto exp_pub_bin_len = public_key_size(pubkey.grp); eph_pub_bin_len != exp_pub_bin_len) {
            ESP_LOGE("KA", "Ephemeral public key length %d differs from expected length %d", eph_pub_bin_len, exp_pub_bin_len);
            return mbedtls_err::other;
        }

        // Prepare an output buffer; copy IV, salt, public key
        const auto enc_message_len = iv.size() + salt.size() + eph_pub_bin_len + plaintext.size() + tag_size;
        mlab::bin_data enc_message;
        enc_message << mlab::prealloc(enc_message_len) << iv << salt;
        // Public key is actually a subset of the binary array:
        enc_message << mlab::make_range(std::begin(eph_pub_bin), std::begin(eph_pub_bin) + eph_pub_bin_len);
        // Preallocation just allocates, now resize to the full required length so that the buffer is available for writing
        enc_message.resize(enc_message_len);

        // Select the data windows for ciphertext and tag
        const auto ciphertext = mlab::make_range(
                std::begin(enc_message) + std::ptrdiff_t(iv.size() + salt.size() + eph_pub_bin_len),
                std::begin(enc_message) + std::ptrdiff_t(iv.size() + salt.size() + eph_pub_bin_len + plaintext.size()));

        const auto tag = mlab::make_range(ciphertext.end(), enc_message.end());

        assert(tag.size() == tag_size);
        assert(ciphertext.size() == std::ptrdiff_t(plaintext.size()));

        MBEDTLS_TRY(mbedtls_gcm_crypt_and_tag(aes_gcm, MBEDTLS_GCM_ENCRYPT, plaintext.size(),
                                              iv.data(), iv.size(), nullptr, 0,
                                              plaintext.data(), ciphertext.data(), tag.size(), tag.data()))
        return enc_message;
    }

    mbedtls_result<std::array<std::uint8_t, 32>> ecies_derive_symmetric_key(std::array<std::uint8_t, 32> const &salt, mbedtls_mpi const &secret) {
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

    mbedtls_result<> ecies_derive_symmetric_key(std::array<std::uint8_t, 32> const &salt, mbedtls_mpi const &secret, mbedtls_gcm_context &context) {
        if (const auto r = ecies_derive_symmetric_key(salt, secret); r) {
            MBEDTLS_TRY(mbedtls_gcm_setkey(&context, MBEDTLS_CIPHER_ID_AES, r->data(), r->size()))
            return mlab::result_success;
        } else {
            return r.error();
        }
    }

}// namespace ka