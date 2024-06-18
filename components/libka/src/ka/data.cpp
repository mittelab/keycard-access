//
// Created by spak on 1/8/23.
//

#include <esp_chip_info.h>
#include <esp_ota_ops.h>
#include <ka/data.hpp>
#include <ka/misc.hpp>
#include <mlab/strutils.hpp>
#include <sodium/crypto_hash_sha512.h>

namespace ka {
    [[nodiscard]] token_id id_from_nfc_id(std::vector<std::uint8_t> const &d) {
        if (d.size() != token_id::array_size) {
            ESP_LOGE("KA", "NFC ID should be %d bytes long, not %d.", token_id::array_size, d.size());
        }
        token_id id{};
        std::copy_n(std::begin(d), std::min(token_id::array_size, d.size()), std::begin(id));
        return id;
    }

    namespace {

        [[nodiscard]] std::optional<std::pair<semver::version, std::string>> parse_git_describe_version(std::string_view v) {
            namespace sv_detail = semver::detail;
            auto next = std::begin(v);
            auto last = std::end(v);
            if (*next == 'v') {
                ++next;
            }
            semver::version sv{};
            if (next = sv_detail::from_chars(next, last, sv.major); sv_detail::check_delimiter(next, last, '.')) {
                if (next = sv_detail::from_chars(++next, last, sv.minor); sv_detail::check_delimiter(next, last, '.')) {
                    if (next = sv_detail::from_chars(++next, last, sv.patch); next == last) {
                        // Parsed version without anything else
                        return std::make_pair(sv, "");
                    } else if (sv_detail::check_delimiter(next, last, '-')) {

                        if (const auto next_after_prerelease = sv_detail::from_chars(++next, last, sv.prerelease_type); next_after_prerelease == nullptr) {
                            // Not a prerelease, it's git stuff
                            return std::make_pair(sv, std::string{next, last});
                        } else if (next = next_after_prerelease; next == last) {
                            // We did parse till the end the prerelease
                            return std::make_pair(sv, "");
                        } else if (sv_detail::check_delimiter(next, last, '.')) {
                            // There is a dot which might identify the prerelease number
                            if (next = sv_detail::from_chars(++next, last, sv.prerelease_number); next == last) {
                                // Reached the end of parsing with the prerelease number
                                return std::make_pair(sv, "");
                            } else if (next == nullptr) {
                                // Could not parse this as a number.
                                return std::nullopt;
                            }
                        }
                        assert(next != last and next != nullptr);
                        // next != last and there is no dot, so it must be git stuff
                        if (sv_detail::check_delimiter(next, last, '-')) {
                            // Skip the hyphen
                            return std::make_pair(sv, std::string{std::next(next), last});
                        }
                    }
                }
            }
            return std::nullopt;
        }

        [[nodiscard]] const char *get_platform_code() {
            static const char *_code = []() {
                esp_chip_info_t chip_info{};
                esp_chip_info(&chip_info);
                switch (chip_info.model) {
                    case CHIP_ESP32:
                        return "esp32";
                    case CHIP_ESP32S2:
                        return "esp32s2";
                    case CHIP_ESP32S3:
                        return "esp32s3";
                    case CHIP_ESP32C3:
                        return "esp32c3";
                    case CHIP_ESP32H2:
                        return "esp32h2";
                    case CHIP_ESP32C2:
                        return "esp32c2";
                    default:
                        return "unknown";
                }
            }();
            return _code;
        }

        [[nodiscard]] std::string escape(std::string_view text) {
            return mlab::replace_all(mlab::replace_all(text, "\\", "\\\\"), "\n", "\\\n");
        }
    }// namespace

    std::string identity::string_representation() const {
        return mlab::data_to_hex_string(id) + "\n" + escape(holder) + "\n" + escape(publisher);
    }

    hash_type identity::hash() const {
        const std::string repr = string_representation();
        const mlab::bin_data data = mlab::bin_data::chain(
                mlab::prealloc(repr.size()),
                mlab::data_view_from_string(repr));
        hash_type h{};
        if (0 != crypto_hash_sha512(h.data(), data.data(), data.size())) {
            ESP_LOGE("KA", "Could not hash text and salt.");
            h = {};
        }
        return h;
    }

    bool identity::operator==(identity const &other) const {
        return id == other.id and holder == other.holder and publisher == other.publisher;
    }

    bool identity::operator!=(identity const &other) const {
        return id != other.id or holder != other.holder or publisher != other.publisher;
    }

    bool fw_info::is_running_fw_pending_verification() {
        const auto *partition = esp_ota_get_running_partition();
        if (partition == nullptr) {
            return false;
        }
        esp_ota_img_states_t state = ESP_OTA_IMG_UNDEFINED;
        esp_err_t r = ESP_FAIL;
        if (ESP_ERROR_CHECK_WITHOUT_ABORT(r = esp_ota_get_state_partition(partition, &state)); r != ESP_OK) {
            return false;
        }
        return state == ESP_OTA_IMG_PENDING_VERIFY;
    }

    void fw_info::running_fw_mark_verified() {
        ESP_ERROR_CHECK_WITHOUT_ABORT(esp_ota_mark_app_valid_cancel_rollback());
    }

    void fw_info::running_fw_rollback() {
        ESP_ERROR_CHECK_WITHOUT_ABORT(esp_ota_mark_app_invalid_rollback_and_reboot());
    }

    std::string fw_info::get_fw_bin_prefix() const {
        return mlab::concatenate({app_name, "-", platform_code});
    }

    fw_info fw_info::get_running_fw() {
        if (const auto *app_desc = esp_app_get_description(); app_desc == nullptr) {
            return {};
        } else {
            fw_info retval{};
            if (const auto sv_commit = parse_git_describe_version(app_desc->version); sv_commit) {
                std::tie(retval.semantic_version, retval.commit_info) = *sv_commit;
            } else {
                ESP_LOGE("KA", "Invalid version %s.", app_desc->version);
                return {};
            }
            retval.app_name = app_desc->project_name;
            retval.platform_code = get_platform_code();
            return retval;
        }
    }

    std::string fw_info::to_string() const {
        if (commit_info.empty()) {
            return mlab::concatenate({app_name, "-", platform_code, "-", semantic_version.to_string()});
        } else {
            return mlab::concatenate({app_name, "-", platform_code, "-", semantic_version.to_string(), "-", commit_info});
        }
    }

}// namespace ka

namespace mlab {

    bin_stream &operator>>(bin_stream &s, ka::identity &id) {
        if (s.remaining() < 7 + 2 + 2) {
            s.set_bad();
            return s;
        }
        s >> id.id;
        std::uint16_t holder_length = 0, publisher_length = 0;
        s >> mlab::lsb16 >> holder_length;
        if (s.bad()) {
            return s;
        }
        if (s.remaining() < holder_length + 2) {
            s.set_bad();
            return s;
        }
        id.holder = data_to_string(s.read(holder_length));
        if (s.bad()) {
            return s;
        }
        s >> mlab::lsb16 >> publisher_length;
        if (s.remaining() < publisher_length) {
            s.set_bad();
            return s;
        }
        id.publisher = data_to_string(s.read(publisher_length));
        return s;
    }

    bin_data &operator<<(bin_data &bd, ka::identity const &id) {
        const auto holder_view = data_view_from_string(id.holder);
        const auto publisher_view = data_view_from_string(id.publisher);
        return bd << prealloc(bd.size() + id.id.size() + holder_view.size() + publisher_view.size() + 4)
                  << id.id
                  << mlab::lsb16 << holder_view.size()
                  << holder_view
                  << mlab::lsb16 << publisher_view.size()
                  << publisher_view;
    }
}// namespace mlab
