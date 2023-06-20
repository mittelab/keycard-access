//
// Created by spak on 6/14/23.
//

#include <ka/device.hpp>

namespace ka {
    device::device() : _kp{}, _ota{}, _device_ns{} {
        if (auto part = nvs::instance().open_default_partition(); part) {
            _device_ns = part->open_namespc("ka-device");
            if (not _device_ns) {
                ESP_LOGE("KA", "Unable to open NVS namespace.");
            }
        } else {
            ESP_LOGE("KA", "Unable to open NVS partition.");
        }
        if (_device_ns) {
            if (const auto r = _device_ns->get_str("update-channel"); r) {
                _ota.set_update_channel(*r);
            }
            if (const auto r = _device_ns->get_u8("update-enabled"); r and *r != 0) {
                _ota.start();
            }
            if (const auto r = _device_ns->get_blob("secret-key"); r) {
                _kp = key_pair{r->data_view()};
            } else {
                configure();
            }
        } else {
            configure();
        }
    }

    void device::configure() {
        _kp.generate_random();
        ESP_LOGI("KA", "Generated random key pair; public key:");
        ESP_LOG_BUFFER_HEX_LEVEL("KA", _kp.raw_pk().data(), _kp.raw_pk().size(), ESP_LOG_INFO);
        if (_device_ns) {
            if (_device_ns->set_blob("secret-key", mlab::bin_data::chain(_kp.raw_sk()))) {
                if (_device_ns->commit()) {
                    return;
                }
            }
        }
        ESP_LOGE("KA", "Unable to save secret key! This makes all encrypted data ephemeral!");
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
        if (_device_ns) {
            _device_ns->set_u8("update-enabled", v ? 1 : 0);
            _device_ns->commit();
        }
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
        if (_device_ns) {
            _device_ns->set_str("update-channel", std::string{channel});
            _device_ns->commit();
        }
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