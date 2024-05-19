//
// Created by spak on 6/6/23.
//

#ifndef KEYCARD_ACCESS_OTA_HPP
#define KEYCARD_ACCESS_OTA_HPP

#include <chrono>
#include <condition_variable>
#include <freertos/FreeRTOS.h>
#include <freertos/task.h>
#include <ka/data.hpp>
#include <ka/misc.hpp>
#include <json.hpp>
#include <thread>

namespace ka {
    namespace {
        using namespace std::chrono_literals;
    }
    class wifi;

    struct release_info {
        semver::version semantic_version{0, 0, 0, semver::prerelease::alpha, 0};
        std::string firmware_url{};

        /**
         * Gets the list of releases from a custom channel with the given binary prefix.
         * @note Assumes that the network is accessible.
         */
        [[nodiscard]] static std::optional<std::vector<release_info>> from_update_channel(std::string_view update_channel, std::string_view fw_bin_prefix);

        /**
         * Converts the JSON list of releases into a list of @ref firmware_release for the given binary prefix.
         */
        [[nodiscard]] static std::vector<release_info> from_update_channel(const nlohmann::json &releases_json, std::string_view fw_bin_prefix);
    };

    class ota_watch {
        TaskHandle_t _t = nullptr;
        std::chrono::minutes _refresh_interval;
        std::condition_variable _stop;
        std::mutex _stop_mutex;
        std::string _update_channel;

        static void thread_body_cbk(void *user_data);
        void thread_body();

    public:
        static constexpr auto default_update_channel = "https://git.mittelab.org/api/v4/projects/31/releases";

        explicit ota_watch(std::chrono::minutes refresh_interval = 1h, std::string_view update_channel = default_update_channel);

        [[nodiscard]] inline std::chrono::minutes refresh_interval() const;
        inline void set_refresh_interval(std::chrono::minutes refresh_interval);
        [[nodiscard]] inline std::string_view update_channel() const;
        inline void set_update_channel(std::string_view update_channel);

        /**
         * Main entry point for update checking.
         * Will return the next release.
         */
        [[nodiscard]] std::optional<release_info> check_now() const;
        [[nodiscard]] std::optional<release_info> check_now(std::string_view update_channel) const;

        /**
         * Returns the url from which the firmware is updating, if any, or nullopt.
         */
        [[nodiscard]] std::optional<std::string> is_updating() const;

        /**
         * Triggers update from a specific url.
         * @param url
         */
        void update_from(std::string_view url);

        [[nodiscard]] bool test_update_channel(std::string_view update_channel) const;

        void start();
        [[nodiscard]] inline bool is_running() const;
        void stop();
    };

}// namespace ka

namespace ka {

    std::chrono::minutes ota_watch::refresh_interval() const {
        return _refresh_interval;
    }
    void ota_watch::set_refresh_interval(std::chrono::minutes refresh_interval) {
        _refresh_interval = std::max(1min, refresh_interval);
    }
    std::string_view ota_watch::update_channel() const {
        return _update_channel;
    }
    void ota_watch::set_update_channel(std::string_view update_channel) {
        _update_channel = update_channel;
    }

    bool ota_watch::is_running() const {
        return _t != nullptr;
    }

}// namespace ka
#endif//KEYCARD_ACCESS_OTA_HPP
