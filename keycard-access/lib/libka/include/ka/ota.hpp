//
// Created by spak on 6/6/23.
//

#ifndef KEYCARD_ACCESS_OTA_HPP
#define KEYCARD_ACCESS_OTA_HPP

#include <chrono>
#include <condition_variable>
#include <neargye/semver.hpp>
#include <nlohmann/json.hpp>
#include <thread>

namespace ka {
    class wifi;

    class ota_watch {
        TaskHandle_t _t = nullptr;
        std::chrono::minutes _refresh_interval;
        std::condition_variable _stop;
        std::mutex _stop_mutex;
        std::weak_ptr<wifi> _wifi;

        static void thread_body_cbk(void *user_data);
        void thread_body();

    public:
        static constexpr auto default_update_channel = "https://git.mittelab.org/api/v4/projects/31/releases";

        ota_watch(std::weak_ptr<wifi> wifi, std::chrono::minutes refresh_interval);

        /**
         * Main entry point for update checking. Will download the next releases and trigger the update if needed.
         */
        void check_now(std::string_view update_channel = default_update_channel);

        /**
         * Triggers update from a specific url.
         * @param url
         */
        void update_from(std::string_view url);

        void start();
        [[nodiscard]] bool is_running();
        void stop();
    };

    using datetime = std::chrono::time_point<std::chrono::system_clock>;

    struct fw_info {
        semver::version semantic_version{};
        std::string commit_info{};
        datetime build_date{};
        std::string app_name{};
        std::string platform_code{};

        [[nodiscard]] static fw_info get_running_fw();

        /**
         * Returns a string that prefixes every version of this firmware, given by "app_name-platform"
         */
        [[nodiscard]] std::string get_fw_bin_prefix() const;

        /**
         * Returns true if and only if an OTA update has just occurred and the firmware was not verified yet.
         * @see
         *  - mark_running_fw_as_verified
         *  - rollback_running_fw
         */
        [[nodiscard]] static bool is_running_fw_pending_verification();

        /**
         * Marks this firmware as safe and prevents rollback on the next boot.
         */
        static void running_fw_mark_verified();

        /**
         * Triggers rollback of the previous fw.
         */
        static void running_fw_rollback();

        [[nodiscard]] std::string to_string() const;
    };

    struct release_info {
        semver::version semantic_version{};
        datetime release_date{};
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

    namespace utils {
        /**
         * Parse C++ dates using C's strptime.
         */
        [[nodiscard]] std::optional<datetime> strptime(std::string_view s, std::string_view fmt);

        /**
         * Formats C++ dates using C's strftime.
         */
        [[nodiscard]] std::string strftime(datetime const &dt, std::string_view fmt);
    }// namespace utils

}// namespace ka
#endif//KEYCARD_ACCESS_OTA_HPP
