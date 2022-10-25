//
// Created by spak on 10/25/22.
//

#ifndef KEYCARDACCESS_SECURE_RNG_HPP
#define KEYCARDACCESS_SECURE_RNG_HPP

#include <array>
#include <ka/helpers.hpp>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/entropy.h>

namespace ka {
    class secure_rng {
        managed<mbedtls_entropy_context, &mbedtls_entropy_init, &mbedtls_entropy_free> _entropy_ctx;
        managed<mbedtls_ctr_drbg_context, &mbedtls_ctr_drbg_init, &mbedtls_ctr_drbg_free> _drbg_ctx;

        static int entropy_source(void *data [[maybe_unused]], unsigned char *output, std::size_t len, std::size_t *olen);

    public:
        typedef int (*rng_fn)(void *, unsigned char *, std::size_t);

        secure_rng();
        secure_rng(secure_rng &&) = delete;
        secure_rng &operator=(secure_rng &&) = delete;

        /**
         * @brief Pointer to the random number generator context.
         */
        [[nodiscard]] void *arg();

        /**
         * @brief Pointer to the random number generator function.
         */
        [[nodiscard]] constexpr rng_fn fn() const;

        /**
         * @brief Fills an array with random bytes from the internal random number generator
         */
        template <std::size_t Len>
        void fill(std::array<std::uint8_t, Len> &a);
    };

    secure_rng &default_secure_rng();

}// namespace ka

namespace ka {
    constexpr secure_rng::rng_fn secure_rng::fn() const {
        return &mbedtls_ctr_drbg_random;
    }

    template <std::size_t Len>
    void secure_rng::fill(std::array<std::uint8_t, Len> &a) {
        fn()(arg(), &a[0], Len);
    }
}// namespace ka

#endif//KEYCARDACCESS_SECURE_RNG_HPP
