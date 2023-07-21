//
// Created by spak on 7/16/23.
//

#include <driver/gpio.h>
#include <ka/gpio_auth_responder.hpp>
#include <mlab/result_macro.hpp>
#include <mutex>
#include <thread>

namespace ka {

    namespace {
        class gpio_responder_global_config {
            gpio_responder_config _cfg = {};
            mutable std::mutex _chg_mtx = {};
            std::shared_ptr<nvs::namespc> _gate_ns = {};

            gpio_responder_global_config() {
                if (const auto p = nvs::instance().open_default_partition(); p) {
                    _gate_ns = p->open_namespc("gate");
                    if (_gate_ns) {
                        if (const auto r = ka::gpio_responder_config::load_from(*_gate_ns); r) {
                            set(*r);
                            return;
                        } else if (r.error() == nvs::error::not_found) {
                            // No worries
                            return;
                        }
                    }
                }
                ESP_LOGW("KA", "Unable to load GPIO configuration.");
            }

        public:
            [[nodiscard]] gpio_responder_config get() const {
                std::unique_lock<std::mutex> lock{_chg_mtx};
                return _cfg;
            }

            bool set(gpio_responder_config cfg) {
                if (cfg.gpio != GPIO_NUM_MAX and not GPIO_IS_VALID_OUTPUT_GPIO(cfg.gpio)) {
                    return false;
                }
                std::unique_lock<std::mutex> lock{_chg_mtx};
                if (_cfg.gpio != GPIO_NUM_MAX) {
                    ESP_ERROR_CHECK_WITHOUT_ABORT(gpio_set_direction(_cfg.gpio, GPIO_MODE_DISABLE));
                }
                if (cfg.gpio != GPIO_NUM_MAX) {
                    ESP_ERROR_CHECK_WITHOUT_ABORT(gpio_set_direction(cfg.gpio, GPIO_MODE_OUTPUT));
                    ESP_ERROR_CHECK_WITHOUT_ABORT(gpio_set_pull_mode(cfg.gpio, cfg.level ? GPIO_PULLDOWN_ONLY : GPIO_PULLUP_ONLY));
                    ESP_ERROR_CHECK_WITHOUT_ABORT(gpio_set_level(cfg.gpio, cfg.level ? 0 : 1));
                }
                _cfg = cfg;
                if (_cfg.gpio != GPIO_NUM_MAX) {
                    ESP_LOGI("KA", "On authentication: set gpio %d to %d for %lld ms", _cfg.gpio, _cfg.level ? 1 : 0, _cfg.hold_time.count());
                } else {
                    ESP_LOGI("KA", "On authentication: do nothing");
                }
                if (_gate_ns) {
                    if (const auto r = _cfg.save_to(*_gate_ns); not r) {
                        MLAB_FAIL_MSG("_cfg.save_to(*_gate_ns)", r);
                    }
                }
                return true;
            }

            void hold() {
                std::unique_lock<std::mutex> lock{_chg_mtx};
                if (_cfg.gpio != GPIO_NUM_MAX) {
                    ESP_ERROR_CHECK_WITHOUT_ABORT(gpio_set_level(_cfg.gpio, _cfg.level ? 1 : 0));
                    std::this_thread::sleep_for(_cfg.hold_time);
                    ESP_ERROR_CHECK_WITHOUT_ABORT(gpio_set_level(_cfg.gpio, _cfg.level ? 0 : 1));
                }
            }

            void async_hold() {
                std::thread t{&gpio_responder_global_config::hold, this};
                t.detach();
            }

            [[nodiscard]] static gpio_responder_global_config &instance() {
                static gpio_responder_global_config _cfg{};
                return _cfg;
            }
        };
    }// namespace

    gpio_responder_config gpio_responder_config::get_global_config() {
        return gpio_responder_global_config::instance().get();
    }

    bool gpio_responder_config::set_global_config(gpio_responder_config cfg) {
        return gpio_responder_global_config::instance().set(cfg);
    }

    void gpio_gate_responder::on_authentication_success(ka::identity const &) {
        gpio_responder_global_config::instance().async_hold();
    }

    nvs::r<> gpio_responder_config::save_to(nvs::namespc &ns) const {
        return ns.set_encode_blob("gpio-responder", *this);
    }

    nvs::r<gpio_responder_config> gpio_responder_config::load_from(nvs::const_namespc const &ns) {
        return ns.get_parse_blob<gpio_responder_config>("gpio-responder");
    }
}// namespace ka

namespace mlab {
    bin_data &operator<<(bin_data &bd, ka::gpio_responder_config const &grc) {
        return bd << static_cast<std::uint8_t>(grc.gpio) << grc.level << lsb32 << std::uint32_t(grc.hold_time.count());
    }

    bin_stream &operator>>(bin_stream &s, ka::gpio_responder_config &grc) {
        std::uint8_t gpio = GPIO_NUM_MAX;
        bool lev = false;
        std::uint32_t ms = 100;
        s >> gpio >> lev >> lsb32 >> ms;
        if (not s.bad()) {
            grc.gpio = static_cast<gpio_num_t>(gpio);
            grc.level = lev;
            grc.hold_time = std::chrono::milliseconds{ms};
        }
        return s;
    }

}// namespace mlab