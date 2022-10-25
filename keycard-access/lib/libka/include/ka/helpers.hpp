//
// Created by spak on 10/23/22.
//

#ifndef KEYCARDACCESS_HELPERS_HPP
#define KEYCARDACCESS_HELPERS_HPP

#include <mbedtls/aes.h>
#include <mbedtls/ecp.h>
#include <mbedtls/error.h>
#include <mbedtls/gcm.h>
#include <mbedtls/hkdf.h>

#define MBEDTLS_TRY_DESC(FN, DESC)                                   \
    if (const auto res = (FN); not mbedtls_err_check(res, (DESC))) { \
        return mbedtls_err_cast(res);                                \
    }

#define MBEDTLS_TRY(FN) MBEDTLS_TRY_DESC(FN, __func__)

namespace ka {

    enum struct mbedtls_err {
        mpi_file_io_error = MBEDTLS_ERR_MPI_FILE_IO_ERROR,
        mpi_bad_input_data = MBEDTLS_ERR_MPI_BAD_INPUT_DATA,
        mpi_invalid_character = MBEDTLS_ERR_MPI_INVALID_CHARACTER,
        mpi_buffer_too_small = MBEDTLS_ERR_MPI_BUFFER_TOO_SMALL,
        mpi_negative_value = MBEDTLS_ERR_MPI_NEGATIVE_VALUE,
        mpi_division_by_zero = MBEDTLS_ERR_MPI_DIVISION_BY_ZERO,
        mpi_not_acceptable = MBEDTLS_ERR_MPI_NOT_ACCEPTABLE,
        mpi_alloc_failed = MBEDTLS_ERR_MPI_ALLOC_FAILED,
        ecp_bad_input_data = MBEDTLS_ERR_ECP_BAD_INPUT_DATA,
        ecp_buffer_too_small = MBEDTLS_ERR_ECP_BUFFER_TOO_SMALL,
        ecp_feature_unavailable = MBEDTLS_ERR_ECP_FEATURE_UNAVAILABLE,
        ecp_verify_failed = MBEDTLS_ERR_ECP_VERIFY_FAILED,
        ecp_alloc_failed = MBEDTLS_ERR_ECP_ALLOC_FAILED,
        ecp_random_failed = MBEDTLS_ERR_ECP_RANDOM_FAILED,
        ecp_invalid_key = MBEDTLS_ERR_ECP_INVALID_KEY,
        ecp_sig_len_mismatch = MBEDTLS_ERR_ECP_SIG_LEN_MISMATCH,
        ecp_hw_accel_failed = MBEDTLS_ERR_ECP_HW_ACCEL_FAILED,
        ecp_in_progress = MBEDTLS_ERR_ECP_IN_PROGRESS,
        hkdf_bad_input_data = MBEDTLS_ERR_HKDF_BAD_INPUT_DATA,
        md_feature_unavailable = MBEDTLS_ERR_MD_FEATURE_UNAVAILABLE,
        md_bad_input_data = MBEDTLS_ERR_MD_BAD_INPUT_DATA,
        md_alloc_failed = MBEDTLS_ERR_MD_ALLOC_FAILED,
        md_file_io_error = MBEDTLS_ERR_MD_FILE_IO_ERROR,
        md_hw_accel_failed = MBEDTLS_ERR_MD_HW_ACCEL_FAILED,
        gcm_auth_failed = MBEDTLS_ERR_GCM_AUTH_FAILED,
        gcm_bad_input = MBEDTLS_ERR_GCM_BAD_INPUT,
        aes_invalid_key_length = MBEDTLS_ERR_AES_INVALID_KEY_LENGTH,
        aes_invalid_input_length = MBEDTLS_ERR_AES_INVALID_INPUT_LENGTH,
        aes_bad_input_data = MBEDTLS_ERR_AES_BAD_INPUT_DATA,
        aes_feature_unavailable = MBEDTLS_ERR_AES_FEATURE_UNAVAILABLE,
        aes_hw_accel_failed = MBEDTLS_ERR_AES_HW_ACCEL_FAILED,
        other = 0x0
    };

    [[nodiscard]] mbedtls_err mbedtls_err_cast(int mbedtls_errno);

    bool mbedtls_err_check(int mbedtls_errno, const char *fn_desc = nullptr);

    template <class T, void (*InitFn)(T *), void (*FreeFn)(T *)>
    class managed {
        T _obj;

    public:
        managed();
        managed(managed const &) = delete;
        managed(managed &&) = delete;

        managed &operator=(managed const &) = delete;
        managed &operator=(managed &&) = delete;

        [[nodiscard]] operator T *();

        [[nodiscard]] operator T const *() const;

        [[nodiscard]] T *operator->();

        [[nodiscard]] T const *operator->() const;


        [[nodiscard]] T &operator*();

        [[nodiscard]] T const &operator*() const;

        ~managed();
    };
}// namespace ka

namespace ka {
    template <class T, void (*InitFn)(T *), void (*FreeFn)(T *)>
    managed<T, InitFn, FreeFn>::managed() : _obj{} {
        InitFn(&_obj);
    }


    template <class T, void (*InitFn)(T *), void (*FreeFn)(T *)>
    managed<T, InitFn, FreeFn>::operator T *() {
        return &_obj;
    }

    template <class T, void (*InitFn)(T *), void (*FreeFn)(T *)>
    managed<T, InitFn, FreeFn>::operator T const *() const {
        return &_obj;
    }

    template <class T, void (*InitFn)(T *), void (*FreeFn)(T *)>
    T *managed<T, InitFn, FreeFn>::operator->() {
        return &_obj;
    }

    template <class T, void (*InitFn)(T *), void (*FreeFn)(T *)>
    T const *managed<T, InitFn, FreeFn>::operator->() const {
        return &_obj;
    }


    template <class T, void (*InitFn)(T *), void (*FreeFn)(T *)>
    T &managed<T, InitFn, FreeFn>::operator*() {
        return _obj;
    }

    template <class T, void (*InitFn)(T *), void (*FreeFn)(T *)>
    T const &managed<T, InitFn, FreeFn>::operator*() const {
        return _obj;
    }

    template <class T, void (*InitFn)(T *), void (*FreeFn)(T *)>
    managed<T, InitFn, FreeFn>::~managed() {
        FreeFn(&_obj);
    }
}// namespace ka

#endif//KEYCARDACCESS_HELPERS_HPP
