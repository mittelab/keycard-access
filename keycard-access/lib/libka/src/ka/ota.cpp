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
        constexpr auto default_update_channel = "https://git.mittelab.org/api/v4/projects/31/releases";

        [[nodiscard]] datetime release_date_from_app_desc(esp_app_desc_t const &app_desc) {
            std::string date_str = app_desc.date;
            date_str += " ";
            date_str += app_desc.time;
            if (auto d = strptime(date_str, "%b %d %Y %H:%M:%S"); d) {
                return *d;
            } else {
                ESP_LOGE(TAG, "Unparseable date format %s", date_str.c_str());
                return {};
            }
        }
    }// namespace

    bool firmware_version::is_running_fw_pending_verification() {
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

    void firmware_version::running_fw_mark_verified() {
        ESP_ERROR_CHECK_WITHOUT_ABORT(esp_ota_mark_app_valid_cancel_rollback());
    }

    void firmware_version::running_fw_rollback() {
        ESP_ERROR_CHECK_WITHOUT_ABORT(esp_ota_mark_app_invalid_rollback_and_reboot());
    }

    std::string firmware_version::get_platform_code() {
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
    }

    firmware_version firmware_version::get_current() {
        if (const auto *app_desc = esp_app_get_description(); app_desc != nullptr) {
            firmware_version retval{};
            retval.string_version = app_desc->version;
            if (retval.string_version.starts_with('v')) {
                retval.string_version = retval.string_version.substr(1);
            }
            if (semver::version v{}; v.from_string_noexcept(retval.string_version)) {
                retval.semantic_version = v;
            }
            retval.release_date = release_date_from_app_desc(*app_desc);
            retval.app_name = app_desc->project_name;
            retval.platform_code = get_platform_code();
            return retval;
        }
        return {};
    }

    std::string firmware_version::to_string() const {
        std::string retval;
        retval.resize(app_name.size() + 64);
        const std::string release_date_s = strftime(release_date, "%Y-%m-%d %H:%M:%S");
        if (semantic_version) {
            const std::string semver_s = semantic_version->to_string();
            std::snprintf(retval.data(), retval.capacity(), "%s-%s %s (%s)", app_name.c_str(), platform_code.c_str(), semver_s.c_str(), release_date_s.c_str());
        } else {
            std::snprintf(retval.data(), retval.capacity(), "%s-%s build %s (%s)", app_name.c_str(), platform_code.c_str(), string_version.c_str(), release_date_s.c_str());
        }
        retval.shrink_to_fit();
        return retval;
    }

    std::optional<std::vector<firmware_release>> firmware_release::get_from_default_update_channel() {
        return get_from_update_channel(default_update_channel, firmware_version::get_platform_code());
    }

    std::optional<std::vector<firmware_release>> firmware_release::get_from_update_channel(std::string const &update_channel) {
        return get_from_update_channel(update_channel, firmware_version::get_platform_code());
    }

    std::optional<std::vector<firmware_release>> firmware_release::get_from_update_channel(std::string const &update_channel, std::string const &fw_bin_prefix) {
        const auto [status, data] = ka::http_client::get(update_channel);
        if (status != 200) {
            ESP_LOGW(TAG, "HTTP error %d for update channel %s", status, update_channel.c_str());
            return std::nullopt;
        }
        const auto payload = nlohmann::json::parse(std::begin(data), std::end(data), nullptr, false);
        if (payload.is_discarded()) {
            ESP_LOGW(TAG, "Invalid JSON payload for update channel %s", update_channel.c_str());
            return std::nullopt;
        }
        ESP_LOGI(TAG, "Successfully retrieved update channel data %s", update_channel.c_str());
        return get_from_update_channel_data(payload, fw_bin_prefix);
    }

    std::string firmware_release::get_expected_firmware_bin_name(std::string fw_bin_prefix) const {
        const auto v_s = semantic_version.to_string();
        fw_bin_prefix.push_back('-');
        fw_bin_prefix += v_s;
        fw_bin_prefix += ".bin";
        return fw_bin_prefix;
    }

    std::vector<firmware_release> firmware_release::get_from_update_channel_data(const nlohmann::json &releases_json, const std::string &fw_bin_prefix) {
        std::vector<firmware_release> retval;
        for (auto const &entry : releases_json) {
            // Does this have the basic fields we need?
            if (not entry.contains("tag_name") or not entry["tag_name"].is_string()) {
                continue;
            }
            if (not entry.contains("released_at") or not entry["released_at"].is_string()) {
                continue;
            }
            if (not entry.contains("links") or not entry["links"].is_array()) {
                continue;
            }
            firmware_release release{};
            // Is it a valid semantic version tag?
            if (const auto s = entry["tag_name"].get<std::string>(); s.starts_with("v")) {
                if (not release.semantic_version.from_string_noexcept(s.substr(1))) {
                    ESP_LOGW(TAG, "Invalid released semantic version %s", s.c_str());
                    continue;
                }
            }
            // Is it a valid release date?
            if (const auto d = strptime(entry["released_at"].get<std::string>(), "%Y-%m-%dT%H:%M:%S"); not d) {
                const auto d_s = entry["released_at"].get<std::string>();
                const auto v_s = release.semantic_version.to_string();
                ESP_LOGW(TAG, "Unable to parse release date %s for version %s.", d_s.c_str(), v_s.c_str());
                continue;
            }
            // Does it have the correct firmware version?
            const auto fw_name = release.get_expected_firmware_bin_name(fw_bin_prefix);
            for (auto const &link : entry["links"]) {
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

    void check_for_updates(wifi &wf) {
        const auto fw_version = firmware_version::get_current();
        {
            const auto fw_version_s = fw_version.to_string();
            ESP_LOGI(TAG, "Checking for updates on firwmare %s...", fw_version_s.c_str());
        }
        if (not wf.ensure_connected()) {
            ESP_LOGW(TAG, "Unable to activate wifi.");
            return;
        }

        const auto releases = firmware_release::get_from_default_update_channel();
        if (not releases) {
            return;
        }

        // Filter those that are older than the current firmware version
        const auto filter = [&](firmware_release const &r) -> bool {
            if (fw_version.semantic_version) {
                // Use semantic version for comparison
                return r.semantic_version > *fw_version.semantic_version;
            } else {
                // Use relase date
                return r.release_date > fw_version.release_date;
            }
        };

        // Would like to use ranges but probably since we also need to take the min, it's best like this
        firmware_release const *next_release = nullptr;
        for (firmware_release const &release : *releases) {
            if (not filter(release)) {
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

        ESP_LOGW(TAG, "There is a new version: %s", next_release->firmware_url.c_str());

        if (not wf.ensure_connected(5s)) {
            ESP_LOGW(TAG, "Unable to activate wifi.");
            return;
        }

        const auto http_cfg = http_client::get_default_config(next_release->firmware_url, nullptr);
        const esp_https_ota_config_t ota_cfg{
                .http_config = &http_cfg,
                .http_client_init_cb = nullptr,
                .bulk_flash_erase = false,
                .partial_http_download = false,
                .max_http_request_size = 0};

        ESP_LOGW(TAG, "Kicking off update...");
        if (esp_https_ota(&ota_cfg) == ESP_OK) {
            ESP_LOGW(TAG, "Update successful. Restarting in 5s.");
            std::this_thread::sleep_for(5s);
            esp_restart();
        } else {
            ESP_LOGE(TAG, "Update failed.");
        }
    }

    update_watch::update_watch(std::weak_ptr<wifi> wifi, std::chrono::minutes refresh_interval) : _refresh_interval{refresh_interval}, _wifi{std::move(wifi)} {}

    void update_watch::start() {
        if (not is_running()) {
            _t = std::thread{&update_watch::thread_body, this};
        }
    }

    void update_watch::stop() {
        if (is_running()) {
            _stop.notify_one();
            _t->join();
            _t = std::nullopt;
        }
    }

    bool update_watch::is_running() {
        return _t != std::nullopt;
    }

    void update_watch::thread_body() {
        std::unique_lock<std::mutex> lock{_stop_mutex};
        std::this_thread::sleep_for(5s);
        while (_stop.wait_for(lock, _refresh_interval) == std::cv_status::timeout) {
            if (auto pwifi = _wifi.lock(); pwifi != nullptr) {
                check_for_updates(*pwifi);
            }
        }
    }

}// namespace ka
