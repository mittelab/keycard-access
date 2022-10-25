//
// Created by spak on 10/25/22.
//

#include <cstring>
#include <esp_random.h>
#include <ka/secure_rng.hpp>

namespace ka {

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
    secure_rng::secure_rng() {
        static constexpr auto pers_str = "keycard_access";
        const auto *pers_str_cast = reinterpret_cast<const unsigned char *>(pers_str);
        MBEDTLS_TRY_RET_VOID(mbedtls_entropy_add_source(_entropy_ctx, &entropy_source, nullptr, 32, MBEDTLS_ENTROPY_SOURCE_STRONG))
        MBEDTLS_TRY_RET_VOID(mbedtls_ctr_drbg_seed(_drbg_ctx, mbedtls_entropy_func, _entropy_ctx, pers_str_cast, std::strlen(pers_str)))
    }

    void *secure_rng::arg() {
        return static_cast<void *>(&_drbg_ctx);
    }

}// namespace ka