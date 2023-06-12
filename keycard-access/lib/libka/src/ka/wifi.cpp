//
// Created by spak on 6/1/23.
//

#include <atomic>
#include <esp_event_base.h>
#include <esp_log.h>
#include <esp_wifi.h>
#include <ka/wifi.hpp>
#include <mlab/time.hpp>
#include <mutex>
#include <nvs_flash.h>

#define TAG "KA-WIFI"

namespace ka {
    namespace {
        [[nodiscard]] bool initialize_flash() {
            auto r = nvs_flash_init();
            if (r == ESP_ERR_NVS_NO_FREE_PAGES or r == ESP_ERR_NVS_NEW_VERSION_FOUND) {
                // Erase and retry
                ESP_LOGW(TAG, "Erasing NVS flash memory, %s.",
                         r == ESP_ERR_NVS_NO_FREE_PAGES ? "no free pages" : "new version found");

                if (ESP_ERROR_CHECK_WITHOUT_ABORT(r = nvs_flash_erase()); r != ESP_OK) {
                    return false;
                }

                // Retry
                r = nvs_flash_init();
            }
            if (r != ESP_OK) {
                ESP_LOGE(TAG, "Could not initialize flash, error %s", esp_err_to_name(r));
                return false;
            }
            return true;
        }

        [[nodiscard]] bool initialize_flash_and_wifi() {
            if (not initialize_flash()) {
                return false;
            }

            esp_err_t r = ESP_OK;
            if (ESP_ERROR_CHECK_WITHOUT_ABORT(r = esp_netif_init()); r != ESP_OK) {
                return false;
            }

            if (ESP_ERROR_CHECK_WITHOUT_ABORT(r = esp_event_loop_create_default()); r != ESP_OK) {
                // Gracefully exit
                ESP_ERROR_CHECK_WITHOUT_ABORT(esp_netif_deinit());
                return false;
            }

            // We cannot catch this gracefully because it aborts...
            esp_netif_create_default_wifi_sta();

            wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();

            if (ESP_ERROR_CHECK_WITHOUT_ABORT(r = esp_wifi_init(&cfg)); r != ESP_OK) {
                // Gracefully exit
                ESP_ERROR_CHECK_WITHOUT_ABORT(esp_event_loop_delete_default());
                ESP_ERROR_CHECK_WITHOUT_ABORT(esp_netif_deinit());
                return false;
            }

            return true;
        }

        /**
         * Thread-safe.
         */
        [[nodiscard]] bool ensure_wifi_initialized() {
            static std::mutex _mutex{};
            static bool did_initialize = false;
            std::lock_guard<std::mutex> guard{_mutex};
            if (not did_initialize) {
                did_initialize = initialize_flash_and_wifi();
            }
            return did_initialize;
        }

        [[nodiscard]] constexpr const char *reason_to_string(std::uint8_t reason) {
            switch (reason) {
                case WIFI_REASON_UNSPECIFIED:
                    return "UNSPECIFIED";
                case WIFI_REASON_AUTH_EXPIRE:
                    return "AUTH_EXPIRE";
                case WIFI_REASON_AUTH_LEAVE:
                    return "AUTH_LEAVE";
                case WIFI_REASON_ASSOC_EXPIRE:
                    return "ASSOC_EXPIRE";
                case WIFI_REASON_ASSOC_TOOMANY:
                    return "ASSOC_TOOMANY";
                case WIFI_REASON_NOT_AUTHED:
                    return "NOT_AUTHED";
                case WIFI_REASON_NOT_ASSOCED:
                    return "NOT_ASSOCED";
                case WIFI_REASON_ASSOC_LEAVE:
                    return "ASSOC_LEAVE";
                case WIFI_REASON_ASSOC_NOT_AUTHED:
                    return "ASSOC_NOT_AUTHED";
                case WIFI_REASON_DISASSOC_PWRCAP_BAD:
                    return "DISASSOC_PWRCAP_BAD";
                case WIFI_REASON_DISASSOC_SUPCHAN_BAD:
                    return "DISASSOC_SUPCHAN_BAD";
                case WIFI_REASON_BSS_TRANSITION_DISASSOC:
                    return "BSS_TRANSITION_DISASSOC";
                case WIFI_REASON_IE_INVALID:
                    return "IE_INVALID";
                case WIFI_REASON_MIC_FAILURE:
                    return "MIC_FAILURE";
                case WIFI_REASON_4WAY_HANDSHAKE_TIMEOUT:
                    return "4WAY_HANDSHAKE_TIMEOUT";
                case WIFI_REASON_GROUP_KEY_UPDATE_TIMEOUT:
                    return "GROUP_KEY_UPDATE_TIMEOUT";
                case WIFI_REASON_IE_IN_4WAY_DIFFERS:
                    return "IE_IN_4WAY_DIFFERS";
                case WIFI_REASON_GROUP_CIPHER_INVALID:
                    return "GROUP_CIPHER_INVALID";
                case WIFI_REASON_PAIRWISE_CIPHER_INVALID:
                    return "PAIRWISE_CIPHER_INVALID";
                case WIFI_REASON_AKMP_INVALID:
                    return "AKMP_INVALID";
                case WIFI_REASON_UNSUPP_RSN_IE_VERSION:
                    return "UNSUPP_RSN_IE_VERSION";
                case WIFI_REASON_INVALID_RSN_IE_CAP:
                    return "INVALID_RSN_IE_CAP";
                case WIFI_REASON_802_1X_AUTH_FAILED:
                    return "802_1X_AUTH_FAILED";
                case WIFI_REASON_CIPHER_SUITE_REJECTED:
                    return "CIPHER_SUITE_REJECTED";
                case WIFI_REASON_TDLS_PEER_UNREACHABLE:
                    return "TDLS_PEER_UNREACHABLE";
                case WIFI_REASON_TDLS_UNSPECIFIED:
                    return "TDLS_UNSPECIFIED";
                case WIFI_REASON_SSP_REQUESTED_DISASSOC:
                    return "SSP_REQUESTED_DISASSOC";
                case WIFI_REASON_NO_SSP_ROAMING_AGREEMENT:
                    return "NO_SSP_ROAMING_AGREEMENT";
                case WIFI_REASON_BAD_CIPHER_OR_AKM:
                    return "BAD_CIPHER_OR_AKM";
                case WIFI_REASON_NOT_AUTHORIZED_THIS_LOCATION:
                    return "NOT_AUTHORIZED_THIS_LOCATION";
                case WIFI_REASON_SERVICE_CHANGE_PERCLUDES_TS:
                    return "SERVICE_CHANGE_PERCLUDES_TS";
                case WIFI_REASON_UNSPECIFIED_QOS:
                    return "UNSPECIFIED_QOS";
                case WIFI_REASON_NOT_ENOUGH_BANDWIDTH:
                    return "NOT_ENOUGH_BANDWIDTH";
                case WIFI_REASON_MISSING_ACKS:
                    return "MISSING_ACKS";
                case WIFI_REASON_EXCEEDED_TXOP:
                    return "EXCEEDED_TXOP";
                case WIFI_REASON_STA_LEAVING:
                    return "STA_LEAVING";
                case WIFI_REASON_END_BA:
                    return "END_BA";
                case WIFI_REASON_UNKNOWN_BA:
                    return "UNKNOWN_BA";
                case WIFI_REASON_TIMEOUT:
                    return "TIMEOUT";
                case WIFI_REASON_PEER_INITIATED:
                    return "PEER_INITIATED";
                case WIFI_REASON_AP_INITIATED:
                    return "AP_INITIATED";
                case WIFI_REASON_INVALID_FT_ACTION_FRAME_COUNT:
                    return "INVALID_FT_ACTION_FRAME_COUNT";
                case WIFI_REASON_INVALID_PMKID:
                    return "INVALID_PMKID";
                case WIFI_REASON_INVALID_MDE:
                    return "INVALID_MDE";
                case WIFI_REASON_INVALID_FTE:
                    return "INVALID_FTE";
                case WIFI_REASON_TRANSMISSION_LINK_ESTABLISH_FAILED:
                    return "TRANSMISSION_LINK_ESTABLISH_FAILED";
                case WIFI_REASON_ALTERATIVE_CHANNEL_OCCUPIED:
                    return "ALTERATIVE_CHANNEL_OCCUPIED";
                case WIFI_REASON_BEACON_TIMEOUT:
                    return "BEACON_TIMEOUT";
                case WIFI_REASON_NO_AP_FOUND:
                    return "NO_AP_FOUND";
                case WIFI_REASON_AUTH_FAIL:
                    return "AUTH_FAIL";
                case WIFI_REASON_ASSOC_FAIL:
                    return "ASSOC_FAIL";
                case WIFI_REASON_HANDSHAKE_TIMEOUT:
                    return "HANDSHAKE_TIMEOUT";
                case WIFI_REASON_CONNECTION_FAIL:
                    return "CONNECTION_FAIL";
                case WIFI_REASON_AP_TSF_RESET:
                    return "AP_TSF_RESET";
                case WIFI_REASON_ROAMING:
                    return "ROAMING";
                case WIFI_REASON_ASSOC_COMEBACK_TIME_TOO_LONG:
                    return "ASSOC_COMEBACK_TIME_TOO_LONG";
                case WIFI_REASON_SA_QUERY_TIMEOUT:
                    return "SA_QUERY_TIMEOUT";
                default:
                    return "UNKNOWN";
            }
        }
    }// namespace

    class wifi::wifi_impl {
        //// FreeRTOS event group to signal when we are connected
        esp_event_handler_instance_t _instance_any_id;
        esp_event_handler_instance_t _instance_got_ip;
        std::atomic<unsigned> _attempts;
        std::atomic<unsigned> _max_attempts;
        std::atomic<wifi_status> _status;
        std::recursive_mutex _mutex;
        std::condition_variable _status_change;
        std::mutex _status_change_mutex;
        bool _is_started;

        static void _wifi_event_handler_cbk(void *context, esp_event_base_t event_base, std::int32_t event_id, void *event_data);

        void handle_wifi_event(esp_event_base_t event_base, std::int32_t event_id, void *event_data);

    public:
        wifi_impl();

        void connect();

        void disconnect();

        void configure(std::string const &ssid, std::string const &pass);

        [[nodiscard]] wifi_status status() const;

        [[nodiscard]] unsigned attempts() const;

        [[nodiscard]] unsigned max_attempts() const;

        void set_max_attempts(unsigned n);

        wifi_status await_status_change(wifi_status old, std::chrono::milliseconds timeout);

        [[nodiscard]] bool await_connection_attempt(std::chrono::milliseconds timeout);

        ~wifi_impl();
    };


    wifi_status wifi::wifi_impl::status() const {
        return _status;
    }

    unsigned wifi::wifi_impl::attempts() const {
        return _attempts;
    }

    unsigned wifi::wifi_impl::max_attempts() const {
        return _max_attempts;
    }

    void wifi::wifi_impl::set_max_attempts(unsigned n) {
        _max_attempts = n;
    }


    void wifi::wifi_impl::_wifi_event_handler_cbk(void *context, esp_event_base_t event_base, std::int32_t event_id, void *event_data) {
        if (auto *impl_ptr = static_cast<wifi_impl *>(context); impl_ptr != nullptr) {
            impl_ptr->handle_wifi_event(event_base, event_id, event_data);
        } else {
            ESP_LOGE(TAG, "Could not track Wifi object.");
        }
    }

    void wifi::wifi_impl::handle_wifi_event(esp_event_base_t event_base, std::int32_t event_id, void *event_data) {
        if (event_base == WIFI_EVENT && event_id == WIFI_EVENT_STA_START) {
            ESP_LOGI(TAG, "Wifi running on core %d.", xPortGetCoreID());
            esp_wifi_connect();
        } else if (event_base == WIFI_EVENT and event_id == WIFI_EVENT_STA_CONNECTED) {
            ESP_LOGI(TAG, "Connected, retrieving ip...");
            _status = wifi_status::getting_ip;
            _status_change.notify_all();
        } else if (event_base == WIFI_EVENT and event_id == WIFI_EVENT_STA_DISCONNECTED) {
            wifi_event_sta_disconnected_t const &disconnected_event_data = *static_cast<wifi_event_sta_disconnected_t *>(event_data);
            if (_status == wifi_status::connecting or _status == wifi_status::getting_ip) {
                if (++_attempts < _max_attempts or _max_attempts == 0) {
                    ESP_LOGW(TAG, "Connection failed (%s), retrying...", reason_to_string(disconnected_event_data.reason));
                    esp_wifi_connect();
                } else {
                    ESP_LOGW(TAG, "Unable to connect to the AP (%s).", reason_to_string(disconnected_event_data.reason));
                    _status = wifi_status::failure;
                    _status_change.notify_all();
                }
            } else {
                ESP_LOGI(TAG, "Disconnected (%s).", reason_to_string(disconnected_event_data.reason));
                _status = wifi_status::idle;
                _status_change.notify_all();
            }
        } else if (event_base == IP_EVENT and event_id == IP_EVENT_STA_GOT_IP) {
            _status = wifi_status::ready;
            _status_change.notify_all();
            ip_event_got_ip_t const &event = *reinterpret_cast<ip_event_got_ip_t *>(event_data);
            ESP_LOGI(TAG, "Connected, IP: %d.%d.%d.%d", IP2STR(&event.ip_info.ip));
            _attempts = 0;
        }
    }

    void wifi::wifi_impl::configure(std::string const &ssid, std::string const &pass) {
        if (not ensure_wifi_initialized()) {
            return;
        }

        wifi_config_t wifi_config = {
                .sta = {
                        .ssid = {/* fill later */},
                        .password = {/* fill later */},
                        .scan_method = WIFI_FAST_SCAN,
                        .bssid_set = false,
                        .bssid = {0, 0, 0, 0, 0, 0},
                        .channel = 0,
                        .listen_interval = 0,
                        .sort_method = WIFI_CONNECT_AP_BY_SIGNAL,
                        .threshold = {
                                .rssi = -127,
                                .authmode = WIFI_AUTH_WPA2_PSK},
                        .pmf_cfg = {.capable = true, .required = false},
                        .rm_enabled = 0,
                        .btm_enabled = 0,
                        .mbo_enabled = 0,
                        .ft_enabled = 0,
                        .owe_enabled = 0,
                        .transition_disable = 0,
                        .reserved = 0,
                        .sae_pwe_h2e = WPA3_SAE_PWE_UNSPECIFIED,
                        .failure_retry_cnt = 0},
        };

        std::fill(std::begin(wifi_config.sta.ssid), std::end(wifi_config.sta.ssid), 0);
        std::fill(std::begin(wifi_config.sta.password), std::end(wifi_config.sta.password), 0);
        std::copy(std::begin(ssid), std::end(ssid), std::begin(wifi_config.sta.ssid));
        std::copy(std::begin(pass), std::end(pass), std::begin(wifi_config.sta.password));

        std::lock_guard<std::recursive_mutex> guard{_mutex};
        _attempts = 0;
        ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_STA));
        ESP_ERROR_CHECK(esp_wifi_set_config(WIFI_IF_STA, &wifi_config));
    }

    wifi::wifi_impl::wifi_impl()
        : _instance_any_id{nullptr},
          _instance_got_ip{nullptr},
          _attempts{0},
          _max_attempts{5},
          _status{wifi_status::idle},
          _mutex{},
          _status_change{},
          _status_change_mutex{},
          _is_started{false} {

        // Must be initialized in order to register instance handlers
        if (not ensure_wifi_initialized()) {
            return;
        }

        ESP_ERROR_CHECK(esp_event_handler_instance_register(
                WIFI_EVENT, ESP_EVENT_ANY_ID, &_wifi_event_handler_cbk, this, &_instance_any_id));
        ESP_ERROR_CHECK(esp_event_handler_instance_register(
                IP_EVENT, IP_EVENT_STA_GOT_IP, &_wifi_event_handler_cbk, this, &_instance_got_ip));
    }

    void wifi::wifi_impl::connect() {
        std::lock_guard<std::recursive_mutex> guard{_mutex};
        if (_status == wifi_status::idle) {
            _status = wifi_status::connecting;
            _status_change.notify_all();
            if (not _is_started) {
                _is_started = true;
                ESP_ERROR_CHECK(esp_wifi_start());
            }
            ESP_ERROR_CHECK(esp_wifi_connect());
        } else if (_status == wifi_status::failure) {
            _attempts = 0;
            _status = wifi_status::connecting;
            _status_change.notify_all();
            ESP_ERROR_CHECK(esp_wifi_connect());
        }
    }

    void wifi::wifi_impl::disconnect() {
        std::lock_guard<std::recursive_mutex> guard{_mutex};
        if (wifi_status_is_on(_status)) {
            ESP_ERROR_CHECK(esp_wifi_disconnect());
        }
    }


    wifi_status wifi::wifi_impl::await_status_change(wifi_status old, std::chrono::milliseconds timeout) {
        /**
         * @note We need to use a _status_change_mutex for locking a condition_variable here because atomics have only
         * a `wait` method and not a `wait_for` method, which we need.
         */
        std::unique_lock<std::mutex> lock{_status_change_mutex};
        mlab::reduce_timeout rt{timeout.count() > 0 ? timeout : std::numeric_limits<std::chrono::milliseconds>::max()};
        wifi_status retval = status();
        for (; rt and retval == old; _status_change.wait_for(lock, rt.remaining())) {
            retval = status();
        }
        return retval;
    }

    bool wifi::wifi_impl::await_connection_attempt(std::chrono::milliseconds timeout) {
        mlab::reduce_timeout rt{timeout.count() > 0 ? timeout : std::numeric_limits<std::chrono::milliseconds>::max()};
        wifi_status s = status();
        for (; rt and (s == wifi_status::connecting or s == wifi_status::getting_ip); s = await_status_change(s, rt.remaining())) {}
        return s == wifi_status::ready;
    }

    wifi::wifi_impl::~wifi_impl() {
        disconnect();
        ESP_ERROR_CHECK(esp_wifi_stop());
        _is_started = false;
        // The event will not be processed after unregister
        if (_instance_any_id != nullptr) {
            ESP_ERROR_CHECK(esp_event_handler_instance_unregister(WIFI_EVENT, ESP_EVENT_ANY_ID, _instance_any_id));
            _instance_any_id = nullptr;
        }
        if (_instance_got_ip != nullptr) {
            ESP_ERROR_CHECK(esp_event_handler_instance_unregister(IP_EVENT, IP_EVENT_STA_GOT_IP, _instance_got_ip));
            _instance_got_ip = nullptr;
        }
    }

    void wifi::wifi_impl_deleter(ka::wifi::wifi_impl *wi) {
        std::default_delete<wifi_impl>{}(wi);
    }

    wifi::wifi() : _pimpl{new wifi_impl(), &wifi_impl_deleter} {}

    wifi::wifi(const std::string &ssid, const std::string &pass, bool auto_connect) : wifi{} {
        reconfigure(ssid, pass, auto_connect);
    }

    void wifi::reconfigure(std::string const &ssid, std::string const &pass, bool auto_connect) {
        if (const auto s = status(); s != wifi_status::idle and s != wifi_status::failure) {
            disconnect();
            await_status_change(s, 20ms);
        }
        _pimpl->configure(ssid, pass);
        if (auto_connect) {
            connect();
        }
    }

    void wifi::connect() {
        _pimpl->connect();
    }

    void wifi::disconnect() {
        _pimpl->disconnect();
    }

    wifi_status wifi::status() const {
        return _pimpl->status();
    }


    wifi_status wifi::await_status_change(wifi_status old, std::chrono::milliseconds timeout) {
        return _pimpl->await_status_change(old, timeout);
    }

    bool wifi::await_connection_attempt(std::chrono::milliseconds timeout) {
        return _pimpl->await_connection_attempt(timeout);
    }

    bool wifi::ensure_connected(std::chrono::milliseconds timeout) {
        switch (status()) {
            case wifi_status::idle:
                [[fallthrough]];
            case wifi_status::failure:
                connect();
                [[fallthrough]];
            case wifi_status::connecting:
                [[fallthrough]];
            case wifi_status::getting_ip:
                return await_connection_attempt(timeout);
            case wifi_status::ready:
                return true;
        }
        return false;
    }

    unsigned wifi::attempts() const {
        return _pimpl->attempts();
    }

    unsigned wifi::max_attempts() const {
        return _pimpl->max_attempts();
    }

    void wifi::set_max_attempts(unsigned n) {
        _pimpl->set_max_attempts(n);
    }

    wifi_session::wifi_session(wifi &wf, bool disconnect_when_done, std::chrono::milliseconds timeout) : _wf{&wf}, _disconnect_when_done{disconnect_when_done} {
        if (_wf->ensure_connected(timeout)) {
            esp_wifi_set_ps(WIFI_PS_NONE);
        }
    }

    wifi_session::wifi_session(ka::wifi &wf, std::chrono::milliseconds timeout) : wifi_session{wf, not wifi_status_is_on(wf.status()), timeout} {}

    wifi_session::operator bool() const {
        return _wf != nullptr and _wf->status() == wifi_status::ready;
    }

    wifi_session::~wifi_session() {
        esp_wifi_set_ps(WIFI_PS_MAX_MODEM);
        if (_wf != nullptr and disconnect_when_done()) {
            _wf->disconnect();
        }
    }
}// namespace ka