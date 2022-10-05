//
// Created by spak on 10/5/22.
//

#ifndef KEYCARDACCESS_KEYS_HPP
#define KEYCARDACCESS_KEYS_HPP

#include <mbedtls/pk.h>
#include <mbedtls/entropy.h>
#include <mbedtls/ctr_drbg.h>
#include <cstdint>
#include <array>

namespace ka {

    class secure_rng {
        mbedtls_entropy_context _entropy_ctx;
        mbedtls_ctr_drbg_context _drbg_ctx;

        static int entropy_source(void *data [[maybe_unused]], unsigned char *output, std::size_t len, std::size_t *olen);
    public:
        typedef int (*rng_fn)(void *, unsigned char *, std::size_t);

        secure_rng();
        secure_rng(secure_rng const &) = delete;
        secure_rng(secure_rng &&) = delete;

        /**
         * @brief Pointer to the random number generator context.
         */
        [[nodiscard]] void *p_rng();

        /**
         * @brief Pointer to the random number generator function.
         */
        [[nodiscard]] constexpr rng_fn rng() const;

        /**
         * @brief Fills an array with random bytes from the internal random number generator
         */
        template <std::size_t Len>
        void fill(std::array<std::uint8_t, Len> &a);

        ~secure_rng();
    };

    class pubkey {
        mbedtls_ecdsa_context _ctx;
    public:
        pubkey();
        ~pubkey();


        pubkey(pubkey const &) = delete;
        pubkey(pubkey &&) noexcept = default;
        pubkey &operator=(pubkey const &) = delete;
        pubkey &operator=(pubkey &&) noexcept = default;

        void generate();

    };
}

namespace ka {
    constexpr secure_rng::rng_fn secure_rng::rng() const {
        return &mbedtls_ctr_drbg_random;
    }

    template <std::size_t Len>
    void secure_rng::fill(std::array<std::uint8_t, Len> &a) {
        rng()(p_rng(), &a[0], Len);
    }
}

#endif//KEYCARDACCESS_KEYS_HPP
