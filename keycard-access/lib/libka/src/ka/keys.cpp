//
// Created by spak on 10/5/22.
//

#include <cstring>
#include <esp_log.h>
#include <esp_random.h>
#include <ka/keys.hpp>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/entropy.h>
#include <mbedtls/error.h>

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

    secure_rng &default_secure_rng() {
        static secure_rng _rng{};
        return _rng;
    }

    int secure_rng::entropy_source(void *data [[maybe_unused]], unsigned char *output, std::size_t len, std::size_t *olen) {
        esp_fill_random(output, len);
        if (olen != nullptr) {
            *olen = len;
        }
        return 0;
    }
    secure_rng::secure_rng() : _entropy_ctx{}, _drbg_ctx{} {
        static constexpr auto pers_str = "keycard_access";
        ESP_LOGI("KA", "Collecting entropy...");
        mbedtls_entropy_init(&_entropy_ctx);
        mbedtls_ctr_drbg_init(&_drbg_ctx);
        MBEDTLS_TRY_RET_VOID(mbedtls_entropy_add_source(&_entropy_ctx, &entropy_source, nullptr, 32, MBEDTLS_ENTROPY_SOURCE_STRONG))
        const auto *pers_str_cast = reinterpret_cast<const unsigned char *>(pers_str);
        MBEDTLS_TRY_RET_VOID(mbedtls_ctr_drbg_seed(&_drbg_ctx, mbedtls_entropy_func, &_entropy_ctx, pers_str_cast, std::strlen(pers_str)))
        ESP_LOGI("KA", "Collecting entropy done.");
    }

    void *secure_rng::p_rng() {
        return static_cast<void *>(&_drbg_ctx);
    }

    secure_rng::~secure_rng() {
        mbedtls_entropy_free(&_entropy_ctx);
    }

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
            return mlab::bin_data::chain(key_format{0x0, true}.as_byte(), std::make_pair(std::cref(_kp->grp), std::cref(_kp->Q)));
        } else {
            return mlab::bin_data::chain(key_format{0x0, false}.as_byte(), _kp->d);
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

    bool keypair::import_key(mlab::bin_data const &data) {
        clear();
        mlab::bin_stream s{data};
        const auto fmt = key_format::from_byte(s.pop());
        if (fmt.version != 0) {
            ESP_LOGW("KA", "Unsupported key format %02x", fmt.version);
            return false;
        }
        // We know this format version 0, has a curve 25519 group
        MBEDTLS_TRY_RET(mbedtls_ecp_group_load(&_kp->grp, MBEDTLS_ECP_DP_CURVE25519), false)
        // Pull out private or public part
        if (fmt.has_private) {
            s >> _kp->d;
        } else {
            s >> std::make_pair(std::cref(_kp->grp), std::ref(_kp->Q));
        }
        // Assert that the stream ends there.
        if (s.bad()) {
            ESP_LOGW("KA", "Invalid key format.");
            clear();
            return false;
        } else if (not s.eof()) {
            ESP_LOGW("KA", "Stray bytes in key sequence.");
            clear();
            return false;
        }
        // Recover public key, if needed
        if (fmt.has_private) {
            if (not mbedtls_err_check(mbedtls_ecp_mul(
                        &_kp->grp, &_kp->Q, &_kp->d, &_kp->grp.G, default_secure_rng().rng(), default_secure_rng().p_rng()))) {
                clear();
                return false;
            }
        }
        // Safety checks
        if (not has_public()) {
            ESP_LOGW("KA", "Invalid public key loaded.");
            clear();
            return false;
        }
        if (has_private() != fmt.has_private) {
            ESP_LOGW("KA", "Invalid private key loaded.");
            clear();
            return false;
        }
        if (fmt.has_private and not has_matching_public_private()) {
            ESP_LOGE("KA", "Unable to recover public key.");
            clear();
            return false;
        }
        return true;
    }

    void keypair::generate() {
        MBEDTLS_TRY_RET_VOID(mbedtls_ecp_gen_key(MBEDTLS_ECP_DP_CURVE25519, _kp, default_secure_rng().rng(), default_secure_rng().p_rng()))
    }


}// namespace ka