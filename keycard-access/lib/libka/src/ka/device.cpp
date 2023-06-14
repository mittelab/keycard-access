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
    device::device() : _kp{}, _wf{std::make_shared<ka::wifi>()}, _ota{_wf} {
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

    nvs::r<> device::clear_settings(nvs::partition &partition) const {
        if (const auto ns = partition.open_namespc("ka-device"); ns != nullptr) {
            TRY(ns->erase("secret-key"));
            TRY(ns->erase("update-channel"));
            TRY(ns->erase("update-enabled"));
            return mlab::result_success;
        }
        return nvs::error::fail;
    }
}// namespace ka