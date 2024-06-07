//
// Created by spak on 5/31/23.
//

#include <array>
#include <chrono>
#include <cstring>
#include <esp_crt_bundle.h>
#include <esp_http_client.h>
#include <esp_log.h>
#include <ka/http.hpp>
#include <string>

#define TAG "KA-HTTP"

namespace ka {
    using namespace std::chrono_literals;

    class http_client::http_client_impl {
        esp_http_client_handle_t _hdl = nullptr;
        mlab::bin_data _buffer;

        [[nodiscard]] esp_err_t handle(esp_http_client_event_t const &evt);

        static esp_err_t _http_event_handler(esp_http_client_event_t *evt) {
            if (evt->user_data != nullptr) {
                return static_cast<http_client_impl *>(evt->user_data)->handle(*evt);
            }
            return ESP_OK;
        }

    public:
        http_client_impl() = default;

        http_client_impl(http_client_impl const &) = delete;
        http_client_impl(http_client_impl &&) = delete;
        http_client_impl &operator=(http_client_impl const &) = delete;
        http_client_impl &operator=(http_client_impl &&) = delete;

        [[nodiscard]] static esp_http_client_config_t get_default_config(std::string_view url, std::chrono::milliseconds timeout = 5s) {
            return {
                    .url = url.data(),
                    .host = nullptr,
                    .port = 0,
                    .username = nullptr,
                    .password = nullptr,
                    .auth_type = HTTP_AUTH_TYPE_NONE,
                    .path = nullptr,
                    .query = nullptr,
                    .cert_pem = nullptr,
                    .cert_len = 0,
                    .client_cert_pem = nullptr,
                    .client_cert_len = 0,
                    .client_key_pem = nullptr,
                    .client_key_len = 0,
                    .client_key_password = nullptr,
                    .client_key_password_len = 0,
                    .user_agent = "ESP-IDF KeyCardAccess",
                    .method = HTTP_METHOD_GET,
                    .timeout_ms = static_cast<int>(timeout.count()),
                    .disable_auto_redirect = false,
                    .max_redirection_count = 0,
                    .max_authorization_retries = 0,
                    .event_handler = nullptr,
                    .transport_type = HTTP_TRANSPORT_UNKNOWN,
                    .buffer_size = 0,
                    .buffer_size_tx = 0,
                    .user_data = nullptr,
                    .is_async = false,
                    .use_global_ca_store = false,
                    .skip_cert_common_name_check = false,
                    .common_name = nullptr,
                    .crt_bundle_attach = esp_crt_bundle_attach,
                    .keep_alive_enable = false,
                    .keep_alive_idle = 0,
                    .keep_alive_interval = 0,
                    .keep_alive_count = 0,
                    .if_name = nullptr,
#if CONFIG_ESP_TLS_USE_DS_PERIPHERAL
                    .ds_data = nullptr
#endif
            };
        }

        explicit http_client_impl(std::string_view url, std::chrono::milliseconds timeout = 5s) : http_client_impl() {
            esp_http_client_config_t cfg = get_default_config(url, timeout);
            cfg.event_handler = &_http_event_handler;
            cfg.user_data = this;
            _hdl = esp_http_client_init(&cfg);
        }

        ~http_client_impl() {
            if (_hdl != nullptr) {
                ESP_ERROR_CHECK(esp_http_client_cleanup(_hdl));
                _hdl = nullptr;
            }
        }

        [[nodiscard]] std::pair<http_status, mlab::bin_data> get() {
            const auto url = this->url();
            ESP_LOGI(TAG, "GET %s", url.c_str());
            _buffer.clear();
            ESP_ERROR_CHECK_WITHOUT_ABORT(esp_http_client_perform(_hdl));
            return {esp_http_client_get_status_code(_hdl), _buffer};
        }

        [[nodiscard]] std::string url() const {
            std::array<char, 256> buffer{};
            ESP_ERROR_CHECK(esp_http_client_get_url(_hdl, buffer.data(), buffer.size()));
            return {std::begin(buffer), std::end(buffer)};
        }
    };

    esp_err_t http_client::http_client_impl::handle(esp_http_client_event_t const &evt) {
        switch (evt.event_id) {
            case HTTP_EVENT_ERROR: {
                const auto url = this->url();
                ESP_LOGW(TAG, "Error processing %s.", url.c_str());
            } break;
            case HTTP_EVENT_ON_CONNECTED: {
                const auto url = this->url();
                ESP_LOGD(TAG, "Connected to %s.", url.c_str());
            } break;
            case HTTP_EVENT_HEADER_SENT:
                ESP_LOGD(TAG, "HTTP_EVENT_HEADER_SENT");
                break;
            case HTTP_EVENT_ON_HEADER:
                ESP_LOGD(TAG, "HTTP_EVENT_ON_HEADER %s: %s", evt.header_key, evt.header_value);
                break;
            case HTTP_EVENT_ON_DATA:
                ESP_LOGD(TAG, "Receiving %d bytes.", evt.data_len);
                _buffer << mlab::make_range(static_cast<std::uint8_t *>(evt.data), static_cast<std::uint8_t *>(evt.data) + evt.data_len);
                break;
            case HTTP_EVENT_ON_FINISH:
                ESP_LOGD(TAG, "HTTP_EVENT_ON_FINISH");
                break;
            case HTTP_EVENT_DISCONNECTED: {
                const auto url = this->url();
                ESP_LOGD(TAG, "Disconnecting from %s.", url.c_str());
            } break;
            case HTTP_EVENT_REDIRECT:
                ESP_LOGD(TAG, "HTTP_EVENT_REDIRECT");
                break;
        }
        return ESP_OK;
    }

    http_client::http_client(std::string_view url, std::chrono::milliseconds timeout)
        : _pimpl{new http_client_impl(url, timeout), &http_client_deleter} {}


    void http_client::http_client_deleter(ka::http_client::http_client_impl *c) {
        std::default_delete<http_client_impl>{}(c);
    }

    std::pair<http_status, mlab::bin_data> http_client::get() {
        return _pimpl->get();
    }

    std::pair<http_status, mlab::bin_data> http_client::get(std::string_view url, std::chrono::milliseconds timeout) {
        http_client c{url, timeout};
        return c.get();
    }

    esp_http_client_config_t http_client::get_default_config(std::string_view url, std::chrono::milliseconds timeout) {
        return http_client_impl::get_default_config(url, timeout);
    }

}// namespace ka