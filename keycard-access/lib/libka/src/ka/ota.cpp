//
// Created by spak on 6/6/23.
//

#include <ctime>
#include <esp_chip_info.h>
#include <esp_https_ota.h>
#include <esp_ota_ops.h>
#include <ka/http.hpp>
#include <ka/ota.hpp>
#include <ka/wifi.hpp>

#define TAG "KA-UPDATE"

namespace ka {

    namespace {
        [[nodiscard]] datetime release_date_from_app_desc(esp_app_desc_t const &app_desc) {
            std::string date_str;
            date_str.resize(std::strlen(app_desc.date) + std::strlen(app_desc.time) + 2);
            std::snprintf(date_str.data(), date_str.capacity(), "%s %s", app_desc.date, app_desc.time);
            date_str.shrink_to_fit();
            if (auto d = utils::strptime(date_str, "%b %d %Y %H:%M:%S"); d) {
                return *d;
            } else {
                ESP_LOGE(TAG, "Unparseable date format %s", date_str.c_str());
                return {};
            }
        }

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

    }// namespace

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
        std::string pfx;
        pfx.resize(app_name.size() + platform_code.size() + 2);
        std::snprintf(pfx.data(), pfx.capacity(), "%s-%s", app_name.c_str(), platform_code.c_str());
        pfx.shrink_to_fit();
        return pfx;
    }

    fw_info fw_info::get_running_fw() {
        if (const auto *app_desc = esp_app_get_description(); app_desc == nullptr) {
            return {};
        } else {
            fw_info retval{};
            if (const auto sv_commit = parse_git_describe_version(app_desc->version); sv_commit) {
                std::tie(retval.semantic_version, retval.commit_info) = *sv_commit;
            } else {
                ESP_LOGE(TAG, "Invalid version %s.", app_desc->version);
                return {};
            }
            retval.build_date = release_date_from_app_desc(*app_desc);
            retval.app_name = app_desc->project_name;
            retval.platform_code = get_platform_code();
            return retval;
        }
    }

    std::string fw_info::to_string() const {
        std::string retval;
        retval.resize(app_name.size() + 128);
        const std::string release_date_s = utils::strftime(build_date, "%Y-%m-%d %H:%M:%S");
        const std::string semver_s = semantic_version.to_string();
        if (commit_info.empty()) {
            std::snprintf(retval.data(), retval.capacity(), "%s-%s-%s (%s)", app_name.c_str(), platform_code.c_str(), semver_s.c_str(), release_date_s.c_str());
        } else {
            std::snprintf(retval.data(), retval.capacity(), "%s-%s-%s-%s (%s)", app_name.c_str(), platform_code.c_str(), semver_s.c_str(), commit_info.c_str(), release_date_s.c_str());
        }
        retval.shrink_to_fit();
        return retval;
    }

    std::optional<std::vector<release_info>> release_info::from_update_channel(std::string_view update_channel, std::string_view fw_bin_prefix) {
        const auto [status, data] = ka::http_client::get(update_channel);
        if (status != 200) {
            ESP_LOGW(TAG, "HTTP error %d for update channel %s", status, update_channel.data());
            return std::nullopt;
        }
        const auto payload = nlohmann::json::parse(std::begin(data), std::end(data), nullptr, false);
        if (payload.is_discarded()) {
            ESP_LOGW(TAG, "Invalid JSON payload for update channel %s", update_channel.data());
            return std::nullopt;
        }
        ESP_LOGI(TAG, "Successfully retrieved update channel data %s", update_channel.data());
        return from_update_channel(payload, fw_bin_prefix);
    }

    std::vector<release_info> release_info::from_update_channel(const nlohmann::json &releases_json, std::string_view fw_bin_prefix) {
        std::vector<release_info> retval;
        for (auto const &entry : releases_json) {
            // Does this have the basic fields we need?
            if (not entry.contains("tag_name") or not entry["tag_name"].is_string()) {
                continue;
            }
            if (not entry.contains("released_at") or not entry["released_at"].is_string()) {
                continue;
            }
            if (not entry.contains("assets") or not entry["assets"].is_object()) {
                continue;
            }
            if (not entry["assets"].contains("links") or not entry["assets"]["links"].is_array()) {
                continue;
            }
            release_info release{};
            // Is it a valid semantic version tag?
            if (const auto s = entry["tag_name"].get<std::string>(); s.starts_with("v")) {
                if (not release.semantic_version.from_string_noexcept(s.substr(1))) {
                    ESP_LOGW(TAG, "Invalid released semantic version %s", s.c_str());
                    continue;
                }
            }
            // Is it a valid release date?
            if (const auto d = utils::strptime(entry["released_at"].get<std::string>(), "%Y-%m-%dT%H:%M:%S"); d) {
                release.release_date = *d;
            } else {
                const auto d_s = entry["released_at"].get<std::string>();
                const auto v_s = release.semantic_version.to_string();
                ESP_LOGW(TAG, "Unable to parse release date %s for version %s.", d_s.c_str(), v_s.c_str());
                continue;
            }

            // What is the expected firmware name for this version?
            const auto fw_name = [&]() -> std::string {
                const auto v_s = release.semantic_version.to_string();
                std::string retval;
                retval.resize(fw_bin_prefix.size() + v_s.size() + 6);
                std::snprintf(retval.data(), retval.capacity(), "%s-%s.bin", fw_bin_prefix.data(), v_s.c_str());
                retval.shrink_to_fit();
                return retval;
            }();

            // Does it have the correct firmware version?
            for (auto const &link : entry["assets"]["links"]) {
                if (link.contains("name") and link.contains("url") and link["url"].is_string() and link["name"] == fw_name) {
                    // Found the correct firmware
                    release.firmware_url = link["url"].get<std::string>();
                    retval.push_back(std::move(release));
                    break;
                }
            }
        }
        return retval;
    }

    ota_watch::ota_watch(std::weak_ptr<wifi> wifi, std::chrono::minutes refresh_interval) : _t{nullptr}, _refresh_interval{refresh_interval}, _wifi{std::move(wifi)} {}

    void ota_watch::start() {
        if (not is_running()) {
            /**
             * @note CONFIG_ESP32_WIFI_TASK_PINNED_TO_CORE_0 set to 1 implies that core 1 is free!
             */
            const unsigned update_thread_core = CONFIG_ESP32_WIFI_TASK_PINNED_TO_CORE_0;
            xTaskCreatePinnedToCore(&thread_body_cbk, "update_watch", CONFIG_PTHREAD_TASK_STACK_SIZE_DEFAULT, this, 2, &_t, update_thread_core);
        }
    }

    void ota_watch::stop() {
        if (is_running()) {
            _stop.notify_one();
            _t = nullptr;
        }
    }

    bool ota_watch::is_running() {
        return _t != nullptr;
    }

    void ota_watch::thread_body_cbk(void *user_data) {
        if (user_data != nullptr) {
            static_cast<ota_watch *>(user_data)->thread_body();
        }
    }

    void ota_watch::update_from(std::string_view url) {
        auto pwifi = _wifi.lock();
        if (pwifi == nullptr) {
            return;
        }

        wifi_session session{*pwifi};
        if (not session) {
            ESP_LOGW(TAG, "Unable to activate wifi.");
            return;
        }


        const auto http_cfg = http_client::get_default_config(url, 30s);
        const esp_https_ota_config_t ota_cfg{
                .http_config = &http_cfg,
                .http_client_init_cb = nullptr,
                .bulk_flash_erase = false,
                .partial_http_download = false,
                .max_http_request_size = 0};

        ESP_LOGW(TAG, "Kicking off update from %s", url.data());
        if (esp_https_ota(&ota_cfg) == ESP_OK) {
            ESP_LOGW(TAG, "Update successful. Restarting in 5s.");
            std::this_thread::sleep_for(5s);
            esp_restart();
        } else {
            ESP_LOGE(TAG, "Update failed.");
        }
    }

    void ota_watch::check_now(std::string_view update_channel) {
        auto pwifi = _wifi.lock();
        if (pwifi == nullptr) {
            return;
        }

        const auto fw_version = fw_info::get_running_fw();
        {
            const auto fw_version_s = fw_version.to_string();
            ESP_LOGI(TAG, "Checking for updates on firwmare %s...", fw_version_s.c_str());
        }

        wifi_session session{*pwifi};
        if (not session) {
            ESP_LOGW(TAG, "Unable to activate wifi.");
            return;
        }

        const auto releases = release_info::from_update_channel(update_channel, fw_version.get_fw_bin_prefix());
        if (not releases) {
            return;
        }

        // Would like to use ranges but probably since we also need to take the min, it's best like this
        release_info const *next_release = nullptr;
        for (release_info const &release : *releases) {
            // Filter those that are older than the current firmware version
            if (release.semantic_version <= fw_version.semantic_version) {
                continue;
            }
            // Select the *immediate best* release
            if (next_release == nullptr or next_release->semantic_version < release.semantic_version) {
                next_release = &release;
            }
        }

        if (next_release == nullptr) {
            ESP_LOGI(TAG, "You are up to date.");
            return;
        }

        {
            const auto v_s = next_release->semantic_version.to_string();
            ESP_LOGW(TAG, "There is a new version: %s", v_s.c_str());
        }

        update_from(next_release->firmware_url);
    }

    void ota_watch::thread_body() {
        std::unique_lock<std::mutex> lock{_stop_mutex};
        ESP_LOGI(TAG, "Update watch thread running on core %d", xPortGetCoreID());
        std::this_thread::sleep_for(5s);
        while (_stop.wait_for(lock, _refresh_interval) == std::cv_status::timeout) {
            check_now();
        }
    }

    namespace utils {
        std::optional<datetime> strptime(std::string_view s, std::string_view fmt) {
            if (std::tm tm{}; ::strptime(s.data(), fmt.data(), &tm) != nullptr) {
                const auto c_time = std::mktime(&tm);
                return std::chrono::system_clock::from_time_t(c_time);
            }
            return std::nullopt;
        }

        std::string strftime(datetime const &dt, std::string_view fmt) {
            std::array<char, 64> buffer{};
            const auto c_time = std::chrono::system_clock::to_time_t(dt);
            const auto *tm = std::localtime(&c_time);
            if (const auto nchars = std::strftime(buffer.data(), buffer.size(), fmt.data(), tm); nchars > 0) {
                return {std::begin(buffer), std::begin(buffer) + nchars};
            }
            return "<date format too long>";
        }
    }// namespace utils

}// namespace ka
