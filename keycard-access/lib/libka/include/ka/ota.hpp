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

    /**
     * Main entry point for update checking. Will download the next releases and trigger the update if needed.
     */
    void check_for_updates(wifi &wf);

    class update_watch {
        std::optional<std::thread> _t;
        std::chrono::minutes _refresh_interval;
        std::condition_variable _stop;
        std::mutex _stop_mutex;
        std::weak_ptr<wifi> _wifi;

        void thread_body();

    public:
        update_watch(std::weak_ptr<wifi> wifi, std::chrono::minutes refresh_interval);

        void start();
        [[nodiscard]] bool is_running();
        void stop();
    };

    using datetime = std::chrono::time_point<std::chrono::system_clock>;

    struct firmware_version {
        std::optional<semver::version> semantic_version{};
        std::string string_version{};
        datetime release_date{};
        std::string app_name{};
        std::string platform_code{};

        [[nodiscard]] static firmware_version get_current();
        [[nodiscard]] static std::string get_platform_code();

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

    struct firmware_release {
        semver::version semantic_version{};
        datetime release_date{};
        std::string firmware_url{};

        /**
         * Just @p fw_bin_prefix + "-" + @ref semantic_version + ".bin".
         */
        [[nodiscard]] std::string get_expected_firmware_bin_name(std::string fw_bin_prefix) const;

        /**
         * Gets the list of releases from the default channel.
         * @note Assumes that the network is accessible.
         */
        [[nodiscard]] static std::optional<std::vector<firmware_release>> get_from_default_update_channel(std::string const &fw_bin_prefix);

        /**
         * Gets the list of releases from a custom channel with the given binary prefix.
         * @note Assumes that the network is accessible.
         */
        [[nodiscard]] static std::optional<std::vector<firmware_release>> get_from_update_channel(std::string const &update_channel, std::string const &fw_bin_prefix);

        /**
         * Converts the JSON list of releases into a list of @ref firmware_release for the given binary prefix.
         */
        [[nodiscard]] static std::vector<firmware_release> get_from_update_channel_data(nlohmann::json const &releases_json, std::string const &fw_bin_prefix);
    };

    /**
     * Parse C++ dates using C's strptime.
     */
    [[nodiscard]] std::optional<datetime> strptime(std::string_view s, std::string_view fmt);

    /**
     * Formats C++ dates using C's strftime.
     */
    [[nodiscard]] std::string strftime(datetime const &dt, std::string_view fmt);

}// namespace ka
#endif//KEYCARD_ACCESS_OTA_HPP
