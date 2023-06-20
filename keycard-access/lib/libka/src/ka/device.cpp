//
// Created by spak on 6/14/23.
//

#include <ka/device.hpp>

#define TRY(EXPR)                                                    \
    if (const auto r = (EXPR); not r) {                              \
        ESP_LOGE("KA", "Failed: %s at %s:%d, %s",                    \
                 esp_err_to_name(static_cast<esp_err_t>(r.error())), \
                 __FILE__, __LINE__, #EXPR);                         \
        return r.error();                                            \
    }

#define TRY_RESULT(EXPR) TRY(EXPR) else

namespace ka {
    device::device() : _kp{}, _ota{} {
        _ota.start();
    }

    nvs::r<> device::save_settings(nvs::partition &partition) const {
        if (not _kp.is_valid()) {
            ESP_LOGE("KA", "Will not save settings for a device that was not configured.");
            return nvs::error::fail;
        }
        if (const auto ns = partition.open_namespc("ka-device"); ns != nullptr) {
            TRY(ns->set_blob("secret-key", mlab::bin_data::chain(_kp.raw_sk())));
            TRY(ns->set_str("update-channel", std::string{_ota.update_channel()}));
            TRY(ns->set_u8("update-enabled", _ota.is_running() ? 0 : 1));
            // WiFi saves and restores itself
            return mlab::result_success;
        }
        return nvs::error::fail;
    }

    nvs::r<> device::load_settings(nvs::partition const &partition) {
        if (const auto ns = partition.open_const_namespc("ka-device"); ns != nullptr) {
            TRY_RESULT(ns->get_blob("secret-key")) {
                _kp = key_pair{sec_key{r->data_view()}};
            }
            TRY_RESULT(ns->get_str("update-channel")) {
                _ota.set_update_channel(*r);
            }
            TRY_RESULT(ns->get_u8("update-enabled")) {
                if (*r == 0) {
                    _ota.stop();
                } else {
                    _ota.start();
                }
            }
            return mlab::result_success;
        }
        return nvs::error::fail;
    }

    bool device::is_configured() const {
        return _kp.is_valid();
    }

    bool device::updates_automatically() const {
        return _ota.is_running();
    }

    void device::set_update_automatically(bool v) {
        if (v) {
            _ota.start();
        } else {
            _ota.stop();
        }
        // TODO save settings
    }

    std::string_view device::update_channel() const {
        return _ota.update_channel();
    }

    bool device::set_update_channel(std::string_view channel, bool test_before) {
        if (test_before) {
            if (not _ota.test_update_channel(channel)) {
                return false;
            }
        }
        _ota.set_update_channel(channel);
        return true;
    }

    std::optional<release_info> device::check_for_updates() const {
        return _ota.check_now();
    }

    fw_info device::get_firmware_info() const {
        return fw_info::get_running_fw();
    }

    void device::update_firmware() {
        if (const auto ri = _ota.check_now(); ri) {
            _ota.update_from(ri->firmware_url);
        }
    }

    void device::update_firmware(std::string_view fw_url) {
        _ota.update_from(fw_url);
    }

    bool device::is_wifi_configured() const {
        return get_wifi_ssid() != std::nullopt;
    }

    std::optional<std::string> device::get_wifi_ssid() const {
        auto &wf = wifi::instance();
        return wf.get_ssid();
    }

    bool device::test_wifi() {
        auto &wf = wifi::instance();
        return wf.ensure_connected();
    }

    bool device::connect_wifi(std::string_view ssid, std::string_view password) {
        auto &wf = wifi::instance();
        wf.reconfigure(ssid, password);
        return wf.ensure_connected();
    }

}// namespace ka