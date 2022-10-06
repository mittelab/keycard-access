//
// Created by spak on 10/5/22.
//

#ifndef KEYCARDACCESS_KEYS_HPP
#define KEYCARDACCESS_KEYS_HPP

#include <array>
#include <cstdint>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/entropy.h>
#include <mbedtls/pk.h>
#include <mlab/bin_data.hpp>

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

    secure_rng &default_secure_rng();

    class keypair {
        /**
         * @note Mutable because methods that do not modify the context, like exporting keys, still require a nonconst ptr
         */
        mutable mbedtls_pk_context _ctx;

        [[nodiscard]] mbedtls_ecdsa_context *ecdsa_context() const;
        [[nodiscard]] mlab::bin_data export_key_internal(bool include_private) const;
        [[nodiscard]] bool import_key_internal(mlab::bin_data const &data, bool is_private, bool ignore_error);

    public:
        keypair();
        ~keypair();

        keypair(keypair const &) = delete;
        keypair(keypair &&) noexcept = default;
        keypair &operator=(keypair const &) = delete;
        keypair &operator=(keypair &&) noexcept = default;

        void generate();
        void clear();

        [[nodiscard]] bool has_public() const;
        [[nodiscard]] bool has_private() const;

        [[nodiscard]] mlab::bin_data export_key() const;
        [[nodiscard]] mlab::bin_data export_key(bool include_private) const;

        [[nodiscard]] bool import_key(mlab::bin_data const &data);
        [[nodiscard]] bool import_key(mlab::bin_data const &data, bool is_private);
    };
}// namespace ka

namespace ka {
    constexpr secure_rng::rng_fn secure_rng::rng() const {
        return &mbedtls_ctr_drbg_random;
    }

    template <std::size_t Len>
    void secure_rng::fill(std::array<std::uint8_t, Len> &a) {
        rng()(p_rng(), &a[0], Len);
    }
}// namespace ka

#endif//KEYCARDACCESS_KEYS_HPP
