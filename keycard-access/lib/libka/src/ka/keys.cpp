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
        bool check_error(int mbedtls_err, const char *desc) {
            if (mbedtls_err != 0) {
                static auto constexpr buffer_length = 200;
                char buffer[buffer_length];
                mbedtls_strerror(mbedtls_err, buffer, buffer_length);
                ESP_LOGE("KA", "Mbedtls failure for %s, error %s", desc, buffer);
                return false;
            }
            return true;
        }
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
        if (not check_error(
                    mbedtls_entropy_add_source(&_entropy_ctx, &entropy_source, nullptr, 32, MBEDTLS_ENTROPY_SOURCE_STRONG),
                    "mbedtls_entropy_add_source")) {
            return;
        }
        const auto *pers_str_cast = reinterpret_cast<const unsigned char *>(pers_str);
        if (not check_error(
                    mbedtls_ctr_drbg_seed(&_drbg_ctx, mbedtls_entropy_func, &_entropy_ctx, pers_str_cast, std::strlen(pers_str)),
                    "mbedtls_ctr_drbg_seed")) {
            return;
        }
        ESP_LOGI("KA", "Collecting entropy done.");
    }

    void *secure_rng::p_rng() {
        return static_cast<void *>(&_drbg_ctx);
    }

    secure_rng::~secure_rng() {
        mbedtls_entropy_free(&_entropy_ctx);
    }

    keypair::keypair() : _ctx{} {
        mbedtls_pk_init(&_ctx);
    }

    keypair::~keypair() {
        mbedtls_pk_free(&_ctx);
    }

    void keypair::clear() {
        mbedtls_pk_free(&_ctx);
        mbedtls_pk_init(&_ctx);
    }

    bool keypair::has_private() const {
        mbedtls_ecp_keypair *ecp_kp = ecp_keypair();
        return ecp_kp != nullptr and mbedtls_ecp_check_privkey(&ecp_kp->grp, &ecp_kp->d) == 0;
    }

    bool keypair::has_public() const {
        mbedtls_ecp_keypair *ecp_kp = ecp_keypair();
        return ecp_kp != nullptr and mbedtls_ecp_check_pubkey(&ecp_kp->grp, &ecp_kp->Q) == 0;
    }

    mbedtls_ecp_keypair *keypair::ecp_keypair() const {
        return mbedtls_pk_ec(_ctx);
    }

    mlab::bin_data keypair::export_key_internal(bool include_private) const {
        // Should be enough for ecc
        std::array<std::uint8_t, 256> buffer{};
        int written_length = 0;
        if (include_private) {
            written_length = mbedtls_pk_write_key_der(&_ctx, buffer.data(), buffer.size());
        } else {
            written_length = mbedtls_pk_write_pubkey_der(&_ctx, buffer.data(), buffer.size());
        }
        if (written_length < 0) {
            check_error(written_length, "mbedtls_pk_write_(pub)key_der");
            return {};
        }
        // Truncate when returning. Note that both functions operate at the END of the buffer!
        return {std::end(buffer) - written_length, std::end(buffer)};
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

    bool keypair::import_key_internal(const mlab::bin_data &data, bool is_private, bool ignore_error) {
        clear();
        bool success = false;
        if (is_private) {
            const auto result = mbedtls_pk_parse_key(&_ctx, data.data(), data.size(), nullptr, 0);
            if (not ignore_error) {
                success = check_error(result, "mbedtls_pk_parse_key");
            } else {
                success = result == 0;
            }
        } else {
            const auto result = mbedtls_pk_parse_public_key(&_ctx, data.data(), data.size());
            if (not ignore_error) {
                success = check_error(result, "mbedtls_pk_parse_public_key");
            } else {
                success = result == 0;
            }
        }
        // Make sure it's ecp
        if (success and mbedtls_pk_can_do(&_ctx, MBEDTLS_PK_ECKEY) == 0) {
            // Not ecp.
            ESP_LOGE("KA", "Unsupported key type %s", mbedtls_pk_get_name(&_ctx));
            success = false;
        }
        // In case of unsuccessful operation, clear
        if (not success) {
            clear();
        }
        return success;
    }

    bool keypair::import_key(const mlab::bin_data &data, bool is_private) {
        return import_key_internal(data, is_private, false);
    }

    bool keypair::import_key(mlab::bin_data const &data) {
        // Simply try
        if (not import_key_internal(data, true, true)) {
            return import_key(data, false);
        }
        return true;
    }

    void keypair::generate() {
        // Do a clean setup initializing as an ecc context
        clear();
        if (not check_error(mbedtls_pk_setup(&_ctx, mbedtls_pk_info_from_type(MBEDTLS_PK_ECKEY)), "mbedtls_pk_setup")) {
            return;
        }
        // Curve 2259 is not supported for saving/loading
        if (not check_error(
                    mbedtls_ecp_gen_key(MBEDTLS_ECP_DP_SECP521R1, ecp_keypair(),
                                        default_secure_rng().rng(), default_secure_rng().p_rng()),
                    "mbedtls_ecp_gen_key")) {
            clear();
            return;
        }
    }


}// namespace ka