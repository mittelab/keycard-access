//
// Created by spak on 10/5/22.
//

#include <cstring>
#include <esp_log.h>
#include <ka/ecies.hpp>
#include <ka/keypair.hpp>
#include <ka/secure_rng.hpp>
#include <mbedtls/ecdsa.h>
#include <mbedtls/md.h>
#include <wolfssl/wolfcrypt/ed25519.h>
#include <wolfssl/wolfcrypt/ecc.h>

namespace ka {
    namespace {
        struct key_format {
            unsigned version = 0x0;
            bool has_private = false;

            constexpr key_format() = default;
            constexpr key_format(unsigned v, bool pvt) : version{v}, has_private{pvt} {}

            [[nodiscard]] constexpr std::uint8_t as_byte() const {
                return std::uint8_t((version << 1) | (has_private ? 0b1 : 0b0));
            }

            [[nodiscard]] static constexpr key_format from_byte(std::uint8_t b) {
                return {unsigned(b) >> 1, (b & 0b1) != 0};
            }
        };

    }// namespace

    void keypair::clear() {
        clear_private();
        mbedtls_ecp_point_free(&_kp->Q);
        mbedtls_ecp_point_init(&_kp->Q);
        assert(not has_public());
    }

    void keypair::clear_private() {
        mbedtls_mpi_free(&_kp->d);
        mbedtls_mpi_init(&_kp->d);
        assert(not has_private());
    }

    bool keypair::has_private() const {
        return mbedtls_ecp_check_privkey(&_kp->grp, &_kp->d) == 0;
    }

    bool keypair::has_public() const {
        return mbedtls_ecp_check_pubkey(&_kp->grp, &_kp->Q) == 0;
    }

    bool keypair::has_matching_public_private() const {
        return has_public() and has_private() and mbedtls_ecp_check_pub_priv(_kp, _kp) == 0;
    }

    mlab::bin_data keypair::export_key_internal(bool include_private) const {
        if (include_private) {
            return mlab::bin_data::chain(key_format{0x0, true}.as_byte(), _kp->d);
        } else {
            return mlab::bin_data::chain(key_format{0x0, false}.as_byte(), std::make_pair(std::cref(_kp->grp), std::cref(_kp->Q)));
        }
    }

    mlab::bin_data keypair::export_key() const {
        if (not has_public()) {
            ESP_LOGE("KA", "Unable to save an empty key.");
            return {};
        } else {
            return export_key_internal(has_private());
        }
    }

    mlab::bin_data keypair::export_key(bool include_private) const {
        if (not has_public()) {
            ESP_LOGE("KA", "Unable to save an empty key.");
            return {};
        } else {
            return export_key_internal(include_private and has_private());
        }
    }

    mbedtls_result<mlab::bin_data> keypair::encrypt(mlab::bin_data const &data) const {
        if (not has_public()) {
            return mbedtls_err::ecp_invalid_key;
        }
        return ecies::encrypt(*_kp, data);
    }

    mbedtls_result<mlab::bin_data> keypair::decrypt(mlab::bin_data const &data) const {
        if (not has_private()) {
            return mbedtls_err::ecp_invalid_key;
        }
        return ecies::decrypt(*_kp, data);
    }

    mbedtls_result<mlab::bin_data> keypair::sign(mlab::bin_data const &data) const {
        if (not has_private()) {
            return mbedtls_err::ecp_invalid_key;
        }
        if (const auto r_hash = hash(data); not r_hash) {
            return r_hash.error();
        } else {
            std::array<std::uint8_t, MBEDTLS_ECDSA_MAX_LEN> buffer{};
            std::size_t written_length = 0;
            MBEDTLS_TRY(mbedtls_ecdsa_write_signature(
                    _kp, MBEDTLS_MD_SHA256,
                    r_hash->data(), r_hash->size(),
                    buffer.data(), &written_length,
                    default_secure_rng().fn(), default_secure_rng().arg()))

            return mlab::bin_data{std::begin(buffer), std::begin(buffer) + written_length};
        }
    }

    mbedtls_result<> keypair::verify(mlab::bin_data const &data, mlab::bin_data const &signature) const {
        if (not has_public()) {
            return mbedtls_err::ecp_invalid_key;
        }
        if (const auto r_hash = hash(data); not r_hash) {
            return r_hash.error();
        } else {
            MBEDTLS_TRY(mbedtls_ecdsa_read_signature(
                    _kp, r_hash->data(), r_hash->size(), signature.data(), signature.size()))
            return mlab::result_success;
        }
    }

    mbedtls_result<std::array<std::uint8_t, 32>> keypair::hash(mlab::bin_data const &data) {
        auto const *digest = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
        if (digest == nullptr) {
            ESP_LOGE("KA", "Unsupported message digest SHA256!?");
            return mbedtls_err::md_feature_unavailable;
        }
        std::array<std::uint8_t, 32> hash{};
        MBEDTLS_TRY(mbedtls_md(digest, data.data(), data.size(), std::begin(hash)))
        return hash;
    }

    mbedtls_result<> keypair::import_key(mlab::bin_data const &data) {
        clear();
        mlab::bin_stream s{data};
        const auto fmt = key_format::from_byte(s.pop());
        if (fmt.version != 0) {
            ESP_LOGW("KA", "Unsupported key format %02x", fmt.version);
            return mbedtls_err::other;
        }
        // We know this format version 0, has a MBEDTLS_ECP_DP_SECP256R1
        MBEDTLS_TRY(mbedtls_ecp_group_load(&_kp->grp, MBEDTLS_ECP_DP_SECP256R1))
        // Pull out private or public part
        if (fmt.has_private) {
            s >> _kp->d;
        } else {
            s >> std::make_pair(std::cref(_kp->grp), std::ref(_kp->Q));
        }
        // Assert that the stream ends there.
        if (s.bad()) {
            ESP_LOGW("KA", "Invalid key format.");
        } else if (not s.eof()) {
            ESP_LOGW("KA", "Stray bytes in key sequence.");
        } else {
            // Recover public key, if needed
            if (fmt.has_private) {
                if (const auto res = mbedtls_ecp_mul(&_kp->grp, &_kp->Q, &_kp->d, &_kp->grp.G, default_secure_rng().fn(), default_secure_rng().arg());
                    not mbedtls_err_check(res)) {
                    clear();
                    return mbedtls_err_cast(res);
                }
            }
            // Safety checks
            if (not has_public()) {
                ESP_LOGW("KA", "Invalid public key loaded.");
            } else if (has_private() != fmt.has_private) {
                ESP_LOGW("KA", "Invalid private key loaded.");
            } else if (fmt.has_private and not has_matching_public_private()) {
                ESP_LOGE("KA", "Unable to recover public key.");
            } else {
                return mlab::result_success;
            }
        }
        clear();
        return mbedtls_err::other;
    }

    mbedtls_result<> keypair::generate() {
        MBEDTLS_TRY(mbedtls_ecp_gen_key(MBEDTLS_ECP_DP_SECP256R1, _kp, default_secure_rng().fn(), default_secure_rng().arg()))
        return mlab::result_success;
    }


}// namespace ka