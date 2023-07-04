//
// Created by spak on 6/6/23.
//

#include <esp_chip_info.h>
#include <esp_https_ota.h>
#include <esp_ota_ops.h>
#include <ka/http.hpp>
#include <ka/misc.hpp>
#include <ka/ota.hpp>
#include <ka/wifi.hpp>
#include <mlab/strutils.hpp>

#define TAG "KA-UPDATE"

namespace ka {

    namespace {

        [[nodiscard]] std::mutex &update_mutex() {
            static std::mutex _mtx;
            return _mtx;
        }

    }// namespace

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

            // What is the expected firmware name for this version?
            const auto fw_name = mlab::concatenate({fw_bin_prefix, "-", release.semantic_version.to_string(), ".bin"});

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

    ota_watch::ota_watch(std::chrono::minutes refresh_interval, std::string_view update_channel)
        : _t{nullptr},
          _refresh_interval{refresh_interval},
          _update_channel{update_channel} {}

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

    void ota_watch::thread_body_cbk(void *user_data) {
        if (user_data != nullptr) {
            static_cast<ota_watch *>(user_data)->thread_body();
        }
    }


    bool ota_watch::test_update_channel(std::string_view update_channel) const {
        wifi_session session;
        if (not session) {
            ESP_LOGW(TAG, "Unable to activate wifi.");
            return false;
        }
        const auto fw_version = fw_info::get_running_fw();
        const auto releases = release_info::from_update_channel(update_channel, fw_version.get_fw_bin_prefix());
        return releases != std::nullopt;
    }

    void ota_watch::update_from(std::string_view url) {
        std::unique_lock<std::mutex> lock{update_mutex(), std::try_to_lock};
        if (not lock.owns_lock()) {
            ESP_LOGW(TAG, "Another update operation is in progress.");
            return;
        }

        wifi_session session;
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

    std::optional<release_info> ota_watch::check_now() const {
        return check_now(update_channel());
    }

    std::optional<release_info> ota_watch::check_now(std::string_view update_channel) const {
        const auto fw_version = fw_info::get_running_fw();
        {
            const auto fw_version_s = fw_version.to_string();
            ESP_LOGI(TAG, "Checking for updates on firwmare %s...", fw_version_s.c_str());
        }

        wifi_session session;
        if (not session) {
            ESP_LOGW(TAG, "Unable to activate wifi.");
            return std::nullopt;
        }

        const auto releases = release_info::from_update_channel(update_channel, fw_version.get_fw_bin_prefix());
        if (not releases) {
            return std::nullopt;
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
            return std::nullopt;
        } else {
            const auto v_s = next_release->semantic_version.to_string();
            ESP_LOGW(TAG, "There is a new version: %s", v_s.c_str());
        }

        return *next_release;
    }

    void ota_watch::thread_body() {
        std::unique_lock<std::mutex> lock{_stop_mutex};
        ESP_LOGI(TAG, "Update watch thread running on core %d", xPortGetCoreID());
        std::this_thread::sleep_for(5s);
        while (_stop.wait_for(lock, _refresh_interval) == std::cv_status::timeout) {
            if (const auto release = check_now(); release) {
                update_from(release->firmware_url);
            }
        }
    }

}// namespace ka
