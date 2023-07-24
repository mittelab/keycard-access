//
// Created by spak on 6/14/23.
//

#include <ka/console.hpp>
#include <ka/device.hpp>
#include <mlab/result_macro.hpp>

using namespace ka::cmd_literals;

#define TAG "KADEV"
#undef MLAB_RESULT_LOG_PREFIX
#define MLAB_RESULT_LOG_PREFIX TAG

namespace ka {

    device_keypair_storage::device_keypair_storage(std::shared_ptr<nvs::namespc> ns) : _ns{std::move(ns)} {
        if (_ns == nullptr) {
            ESP_LOGE(TAG, "You must specify a nonempty namespace.");
        }
    }

    bool device_keypair_storage::exists() {
        if (_ns == nullptr) {
            return false;
        }
        return bool(_ns->get_blob("secret-key"));
    }

    std::optional<key_pair> device_keypair_storage::load(std::string_view password) {
        if (_ns == nullptr) {
            return std::nullopt;
        }
        if (const auto r = _ns->get_blob("secret-key"); not r) {
            if (r.error() != nvs::error::not_found) {
                MLAB_FAIL_MSG("_ns->get_blob(\"secret-key\")", r);
            }
            return std::nullopt;
        } else {
            return key_pair::load_encrypted(*r, password);
        }
    }

    void device_keypair_storage::save(const ka::key_pair &kp, std::string_view password) {
        if (_ns != nullptr) {
            if (const auto r = _ns->set_blob("secret-key", kp.save_encrypted(password)); not r) {
                MLAB_FAIL_MSG("_ns->set_blob(\"secret-key\")", r);
            }
        }
    }

    device::device(std::shared_ptr<nvs::partition> const &partition) : device{} {
        setup_ns_and_ota(partition);
        load_or_generate_keys();
    }

    device::device(std::shared_ptr<nvs::partition> const &partition, std::string_view password) : device{} {
        setup_ns_and_ota(partition);
        _kp = key_pair{pwhash, password};
        ESP_LOGI(TAG, "Loaded key pair; public key:");
        ESP_LOG_BUFFER_HEX_LEVEL(TAG, _kp.raw_pk().data(), _kp.raw_pk().size(), ESP_LOG_INFO);
    }

    device::device(key_pair kp) {
        _kp = kp;
    }

    void device::setup_ns_and_ota(const std::shared_ptr<nvs::partition> &partition) {
        _ota = std::make_unique<ota_watch>();
        if (partition) {
            _device_ns = partition->open_namespc("ka-device");
        }
        if (_device_ns) {
            // Now get update stuff
            if (const auto r = _device_ns->get_str("update-channel"); r) {
                _ota->set_update_channel(*r);
            } else if (r.error() == nvs::error::not_found) {
                set_update_channel(update_channel(), false);
            } else {
                ESP_LOGE(TAG, "Unable to retrieve %s, error %s", "update channel", to_string(r.error()));
            }

            if (const auto r = _device_ns->get_u8("update-enabled"); r) {
                if (*r != 0) {
                    _ota->start();
                }
            } else if (r.error() == nvs::error::not_found) {
                set_update_automatically(updates_automatically());
            } else {
                ESP_LOGE(TAG, "Unable to retrieve %s, error %s", "update enable flag", to_string(r.error()));
            }
        }
    }

    void device::load_or_generate_keys() {
        if (_device_ns) {
            if (const auto r = _device_ns->get_parse_blob<key_pair>("secret-key"); r) {
                _kp = *r;
                ESP_LOGI(TAG, "Loaded key pair; public key:");
                ESP_LOG_BUFFER_HEX_LEVEL(TAG, _kp.raw_pk().data(), _kp.raw_pk().size(), ESP_LOG_INFO);
                return;
            } else if (r.error() != nvs::error::not_found) {
                ESP_LOGE(TAG, "Unable to retrieve %s, error %s", "secret key", to_string(r.error()));
            }
        }
        generate_keys();
    }

    void device::generate_keys() {
        _kp.generate_random();
        ESP_LOGI(TAG, "Generated random key pair; public key:");
        ESP_LOG_BUFFER_HEX_LEVEL(TAG, _kp.raw_pk().data(), _kp.raw_pk().size(), ESP_LOG_INFO);
        if (_device_ns) {
#ifndef CONFIG_NVS_ENCRYPTION
            ESP_LOGW(TAG, "Encryption is disabled!");
#endif
            auto update_nvs = [&]() -> nvs::r<> {
                TRY(_device_ns->set_encode_blob("secret-key", _kp));
                TRY(_device_ns->commit());
                return mlab::result_success;
            };

            if (not update_nvs()) {
                ESP_LOGE(TAG, "Unable to save secret key! This makes all encrypted data ephemeral!");
            }
        }
    }

    bool device::updates_automatically() const {
        if (not _ota) {
            return false;
        }
        return _ota->is_running();
    }

    void device::set_update_automatically(bool v) {
        if (not _ota) {
            ESP_LOGE(TAG, "Updates not available during test.");
            return;
        }
        if (v) {
            _ota->start();
        } else {
            _ota->stop();
        }
        if (_device_ns) {
            void([&]() -> nvs::r<> {
                TRY(_device_ns->set_u8("update-enabled", v ? 1 : 0));
                TRY(_device_ns->commit());
                return mlab::result_success;
            }());
        }
    }

    std::string_view device::update_channel() const {
        if (not _ota) {
            return "";
        }
        return _ota->update_channel();
    }

    bool device::set_update_channel(std::string_view channel, bool test_before) {
        if (not _ota) {
            ESP_LOGE(TAG, "Updates not available during test.");
            return false;
        }
        if (test_before) {
            if (not _ota->test_update_channel(channel)) {
                return false;
            }
        }
        _ota->set_update_channel(channel);
        if (_device_ns) {
            void([&]() -> nvs::r<> {
                TRY(_device_ns->set_str("update-channel", channel));
                TRY(_device_ns->commit());
                return mlab::result_success;
            }());
        }
        return true;
    }

    std::optional<release_info> device::check_for_updates() const {
        if (not _ota) {
            ESP_LOGE(TAG, "Updates not available during test.");
            return std::nullopt;
        }
        return _ota->check_now();
    }

    fw_info device::get_firmware_info() const {
        return fw_info::get_running_fw();
    }

    void device::update_now() {
        if (not _ota) {
            ESP_LOGE(TAG, "Updates not available during test.");
            return;
        }
        if (const auto ri = _ota->check_now(); ri) {
            _ota->update_from(ri->firmware_url);
        }
    }

    void device::update_manually(std::string_view fw_url) {
        if (not _ota) {
            ESP_LOGE(TAG, "Updates not available during test.");
            return;
        }
        _ota->update_from(fw_url);
    }

    update_status device::is_updating() const {
        if (not _ota) {
            return {std::nullopt};
        }
        return {_ota->is_updating()};
    }

    bool device::wifi_is_configured() const {
        return wifi_get_ssid() != std::nullopt;
    }

    std::optional<std::string> device::wifi_get_ssid() const {
        auto &wf = wifi::instance();
        return wf.get_ssid();
    }

    bool device::wifi_test() {
        auto &wf = wifi::instance();
        return wf.ensure_connected();
    }

    bool device::wifi_connect(std::string_view ssid, std::string_view password) {
        auto &wf = wifi::instance();
        wf.reconfigure(ssid, password);
        return wf.ensure_connected();
    }
    namespace cmd {
        template <>
        struct parser<fw_info> {
            [[nodiscard]] static std::string to_string(fw_info const &fi) {
                return fi.to_string();
            }
        };

        std::string parser<update_status>::to_string(update_status const &us) {
            if (us.updating_from) {
                return mlab::concatenate({"updating from ", *us.updating_from});
            } else {
                return "up to date";
            }
        }

        std::string parser<release_info>::to_string(release_info const &ri) {
            return mlab::concatenate({"New release! ", ri.semantic_version.to_string(), ", url: ", ri.firmware_url});
        }
    }// namespace cmd

    void device::register_commands(cmd::shell &sh) {
        sh.register_command("wifi-connect", *this, &device::wifi_connect, {{"ssid"}, {"password"}});
        sh.register_command("wifi-test", *this, &device::wifi_test, {});
        sh.register_command("wifi-is-configured", *this, &device::wifi_is_configured, {});
        sh.register_command("wifi-get-ssid", *this, &device::wifi_get_ssid, {});
        sh.register_command("update-is-automated", *this, &device::updates_automatically, {});
        sh.register_command("update-set-automated", *this, &device::set_update_automatically, {"toggle"_pos});
        sh.register_command("update-get-channel", *this, &device::update_channel, {});
        sh.register_command("update-set-channel", *this, &device::set_update_channel, {"channel"_pos, ka::cmd::flag{"test", true}});
        sh.register_command("update-is-running", *this, &device::is_updating, {});
        sh.register_command("update-now", *this, &device::update_now, {});
        sh.register_command("update-manually", *this, &device::update_manually, {"firmware-url"_pos});
        sh.register_command("update-check-only", *this, &device::check_for_updates, {});
        sh.register_command("update-get-current-version", *this, &device::get_firmware_info, {});
    }

}// namespace ka