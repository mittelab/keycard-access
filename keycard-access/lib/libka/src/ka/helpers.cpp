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

namespace mlab {
    bin_data &operator<<(bin_data &bd, mbedtls_mpi const &n) {
        const auto n_size = mbedtls_mpi_size(&n);
        assert(n_size < std::numeric_limits<std::uint16_t>::max());
        bd << prealloc(bd.size() + n_size + 2) << lsb16 << n_size;
        const auto n_offset = bd.size();
        bd.resize(bd.size() + n_size);
        ka::mbedtls_err_check(mbedtls_mpi_write_binary_le(&n, bd.data() + n_offset, n_size), "mbedtls_mpi_write_binary_le");
        return bd;
    }

    bin_data &operator<<(bin_data &bd, std::pair<std::reference_wrapper<mbedtls_ecp_group const>, std::reference_wrapper<mbedtls_ecp_point const>> group_and_pt) {
        mbedtls_ecp_group const &group = group_and_pt.first;
        mbedtls_ecp_point const &pt = group_and_pt.second;

        // This buffer suffices for all points:
        std::array<std::uint8_t, MBEDTLS_ECP_MAX_PT_LEN> buffer{};
        std::size_t written_length = 0;
        ka::mbedtls_err_check(mbedtls_ecp_point_write_binary(&group, &pt, MBEDTLS_ECP_PF_UNCOMPRESSED, &written_length, buffer.data(), buffer.size()));
        assert(written_length < std::numeric_limits<std::uint16_t>::max());

        auto buffer_view = make_range(std::begin(buffer), std::begin(buffer) + written_length);

        return bd << prealloc(bd.size() + written_length + 2) << lsb16 << written_length << buffer_view;
    }

    bin_stream &operator>>(bin_stream &s, mbedtls_mpi &n) {
        if (s.remaining() < 2) {
            s.set_bad();
            return s;
        }
        std::size_t nsize = 0;
        s >> lsb16 >> nsize;
        auto buffer = s.read(nsize);
        if (not s.bad()) {
            if (not ka::mbedtls_err_check(mbedtls_mpi_read_binary_le(&n, buffer.data(), buffer.size()), "mbedtls_mpi_read_binary_le")) {
                s.set_bad();
            }
        }
        return s;
    }

    bin_stream &operator>>(bin_stream &s, std::pair<std::reference_wrapper<mbedtls_ecp_group const>, std::reference_wrapper<mbedtls_ecp_point>> group_and_pt) {
        mbedtls_ecp_group const &group = group_and_pt.first;
        mbedtls_ecp_point &pt = group_and_pt.second;

        if (s.remaining() < 2) {
            s.set_bad();
            return s;
        }
        std::size_t nsize = 0;
        s >> lsb16 >> nsize;

        auto buffer = s.read(nsize);
        if (not s.bad()) {
            if (not ka::mbedtls_err_check(mbedtls_ecp_point_read_binary(&group, &pt, buffer.data(), buffer.size()), "mbedtls_ecp_point_read_binary")) {
                s.set_bad();
            }
        }
        return s;
    }
}// namespace mlab