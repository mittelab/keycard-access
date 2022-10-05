//
// Created by spak on 10/5/22.
//

#include "keys.hpp"
#include <cstring>
#include <esp_log.h>
#include <esp_random.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/entropy.h>

namespace ka {

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
        if (0 != mbedtls_entropy_add_source(&_entropy_ctx, &entropy_source, nullptr, 32, MBEDTLS_ENTROPY_SOURCE_STRONG)) {
            ESP_LOGE("KA", "Unable to add esp_fill_random as an entropy source.");
        }
        ESP_LOGI("KA", "Seeding RNG...");
        const auto *const pers_str_cast = reinterpret_cast<const unsigned char *const>(pers_str);
        if (0 != mbedtls_ctr_drbg_seed(&_drbg_ctx, mbedtls_entropy_func, &_entropy_ctx, pers_str_cast, std::strlen(pers_str))) {
            ESP_LOGE("KA", "Unable to seed the random number generator.");
        }
        ESP_LOGI("KA", "Entropy source ready for generation.");
    }

    void *secure_rng::p_rng() {
        return static_cast<void *>(&_drbg_ctx);
    }

    secure_rng::~secure_rng() {
        mbedtls_entropy_free(&_entropy_ctx);
    }

    pubkey::pubkey() : _ctx{} {
        mbedtls_ecdsa_init(&_ctx);
    }

    pubkey::~pubkey() {
        mbedtls_ecdsa_free(&_ctx);
    }

    void pubkey::generate() {
        secure_rng rng;
        mbedtls_ecdsa_genkey(&_ctx, mbedtls_ecp_group_id::MBEDTLS_ECP_DP_CURVE25519, rng.rng(), rng.p_rng());
    }


}// namespace ka