//
// Created by spak on 10/5/22.
//

#include "keys.hpp"
#include <cstring>
#include <esp_log.h>
#include <esp_random.h>
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
        mbedtls_entropy_init(&_entropy_ctx);
        mbedtls_ctr_drbg_init(&_drbg_ctx);
        ESP_LOGI("KA", "Adding esp_fill_random as entropy source.");
        if (not check_error(
                    mbedtls_entropy_add_source(&_entropy_ctx, &entropy_source, nullptr, 32, MBEDTLS_ENTROPY_SOURCE_STRONG),
                    "mbedtls_entropy_add_source")) {
            return;
        }
        ESP_LOGI("KA", "Seeding RNG...");
        const auto *pers_str_cast = reinterpret_cast<const unsigned char *>(pers_str);
        if (not check_error(
                    mbedtls_ctr_drbg_seed(&_drbg_ctx, mbedtls_entropy_func, &_entropy_ctx, pers_str_cast, std::strlen(pers_str)),
                    "mbedtls_ctr_drbg_seed")) {
            return;
        }
        ESP_LOGI("KA", "Entropy source ready for generation.");
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
        mbedtls_ecdsa_context *ecdsa_ctx = ecdsa_context();
        return ecdsa_ctx != nullptr and mbedtls_ecp_check_privkey(&ecdsa_ctx->grp, &ecdsa_ctx->d) == 0;
    }

    bool keypair::has_public() const {
        mbedtls_ecdsa_context *ecdsa_ctx = ecdsa_context();
        return ecdsa_ctx != nullptr and mbedtls_ecp_check_pubkey(&ecdsa_ctx->grp, &ecdsa_ctx->Q) == 0;
    }

    mbedtls_ecdsa_context *keypair::ecdsa_context() const {
        return mbedtls_pk_ec(_ctx);
    }

    mlab::bin_data keypair::export_key_internal(bool include_private) const {
        mlab::bin_data buffer;
        buffer.resize(64);// Should be enough for ecdsa
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
        // Truncate
        buffer.resize(written_length);
        return buffer;
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
        // Make sure it's ecdsa
        if (mbedtls_pk_can_do(&_ctx, MBEDTLS_PK_ECDSA) == 0) {
            // Not ecdsa.
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
    }

    void keypair::generate() {
        // Do a clean setup initializing as an ecdsa context
        clear();
        if (not check_error(mbedtls_pk_setup(&_ctx, mbedtls_pk_info_from_type(MBEDTLS_PK_ECDSA)), "mbedtls_pk_setup")) {
            return;
        }
        // Initialize a suitable entropy source
        if (not check_error(
                    mbedtls_ecdsa_genkey(ecdsa_context(), mbedtls_ecp_group_id::MBEDTLS_ECP_DP_CURVE25519,
                                         default_secure_rng().rng(), default_secure_rng().p_rng()),
                    "mbedtls_ecdsa_genkey")) {
            clear();
            return;
        }
    }


}// namespace ka