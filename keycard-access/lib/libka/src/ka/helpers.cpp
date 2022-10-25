//
// Created by spak on 10/25/22.
//

#include <esp_log.h>
#include <ka/helpers.hpp>

namespace ka {
    [[nodiscard]] mbedtls_err mbedtls_err_cast(int mbedtls_errno) {
        switch (mbedtls_errno) {
            case MBEDTLS_ERR_MPI_FILE_IO_ERROR:
                return mbedtls_err::mpi_file_io_error;
            case MBEDTLS_ERR_MPI_BAD_INPUT_DATA:
                return mbedtls_err::mpi_bad_input_data;
            case MBEDTLS_ERR_MPI_INVALID_CHARACTER:
                return mbedtls_err::mpi_invalid_character;
            case MBEDTLS_ERR_MPI_BUFFER_TOO_SMALL:
                return mbedtls_err::mpi_buffer_too_small;
            case MBEDTLS_ERR_MPI_NEGATIVE_VALUE:
                return mbedtls_err::mpi_negative_value;
            case MBEDTLS_ERR_MPI_DIVISION_BY_ZERO:
                return mbedtls_err::mpi_division_by_zero;
            case MBEDTLS_ERR_MPI_NOT_ACCEPTABLE:
                return mbedtls_err::mpi_not_acceptable;
            case MBEDTLS_ERR_MPI_ALLOC_FAILED:
                return mbedtls_err::mpi_alloc_failed;
            case MBEDTLS_ERR_ECP_BAD_INPUT_DATA:
                return mbedtls_err::ecp_bad_input_data;
            case MBEDTLS_ERR_ECP_BUFFER_TOO_SMALL:
                return mbedtls_err::ecp_buffer_too_small;
            case MBEDTLS_ERR_ECP_FEATURE_UNAVAILABLE:
                return mbedtls_err::ecp_feature_unavailable;
            case MBEDTLS_ERR_ECP_VERIFY_FAILED:
                return mbedtls_err::ecp_verify_failed;
            case MBEDTLS_ERR_ECP_ALLOC_FAILED:
                return mbedtls_err::ecp_alloc_failed;
            case MBEDTLS_ERR_ECP_RANDOM_FAILED:
                return mbedtls_err::ecp_random_failed;
            case MBEDTLS_ERR_ECP_INVALID_KEY:
                return mbedtls_err::ecp_invalid_key;
            case MBEDTLS_ERR_ECP_SIG_LEN_MISMATCH:
                return mbedtls_err::ecp_sig_len_mismatch;
            case MBEDTLS_ERR_ECP_HW_ACCEL_FAILED:
                return mbedtls_err::ecp_hw_accel_failed;
            case MBEDTLS_ERR_ECP_IN_PROGRESS:
                return mbedtls_err::ecp_in_progress;
            case MBEDTLS_ERR_HKDF_BAD_INPUT_DATA:
                return mbedtls_err::hkdf_bad_input_data;
            case MBEDTLS_ERR_MD_FEATURE_UNAVAILABLE:
                return mbedtls_err::md_feature_unavailable;
            case MBEDTLS_ERR_MD_BAD_INPUT_DATA:
                return mbedtls_err::md_bad_input_data;
            case MBEDTLS_ERR_MD_ALLOC_FAILED:
                return mbedtls_err::md_alloc_failed;
            case MBEDTLS_ERR_MD_FILE_IO_ERROR:
                return mbedtls_err::md_file_io_error;
            case MBEDTLS_ERR_MD_HW_ACCEL_FAILED:
                return mbedtls_err::md_hw_accel_failed;
            case MBEDTLS_ERR_GCM_AUTH_FAILED:
                return mbedtls_err::gcm_auth_failed;
            case MBEDTLS_ERR_GCM_BAD_INPUT:
                return mbedtls_err::gcm_bad_input;
            case MBEDTLS_ERR_AES_INVALID_KEY_LENGTH:
                return mbedtls_err::aes_invalid_key_length;
            case MBEDTLS_ERR_AES_INVALID_INPUT_LENGTH:
                return mbedtls_err::aes_invalid_input_length;
            case MBEDTLS_ERR_AES_BAD_INPUT_DATA:
                return mbedtls_err::aes_bad_input_data;
            case MBEDTLS_ERR_AES_FEATURE_UNAVAILABLE:
                return mbedtls_err::aes_feature_unavailable;
            case MBEDTLS_ERR_AES_HW_ACCEL_FAILED:
                return mbedtls_err::aes_hw_accel_failed;
            default:
                return mbedtls_err::other;
        }
    }

    bool mbedtls_err_check(int mbedtls_errno, const char *fn_desc) {
        if (mbedtls_errno != 0) {
            static auto constexpr buffer_length = 200;
            char buffer[buffer_length];
            mbedtls_strerror(mbedtls_errno, buffer, buffer_length);
            if (fn_desc != nullptr) {
                ESP_LOGE("KA", "Mbedtls failure for %s, error %s", fn_desc, buffer);
            } else {
                ESP_LOGE("KA", "Mbedtls error %s", buffer);
            }
            return false;
        }
        return true;
    }
}// namespace ka