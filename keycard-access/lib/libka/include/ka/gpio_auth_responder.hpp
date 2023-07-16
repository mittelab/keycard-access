//
// Created by spak on 7/16/23.
//

#ifndef KEYCARD_ACCESS_GPIO_AUTH_RESPONDER_HPP
#define KEYCARD_ACCESS_GPIO_AUTH_RESPONDER_HPP

#include <chrono>
#include <hal/gpio_types.h>
#include <ka/gate.hpp>

namespace ka {
    namespace {
        using namespace std::chrono_literals;
    }

    struct gpio_responder_config {
        gpio_num_t gpio = GPIO_NUM_MAX;
        bool level = false;
        std::chrono::milliseconds hold_time = 100ms;

        [[nodiscard]] static gpio_responder_config get_global_config();
        static void set_global_config(gpio_responder_config cfg);

        nvs::r<> save_to(nvs::namespc &ns) const;
        [[nodiscard]] static nvs::r<gpio_responder_config> load_from(nvs::const_namespc const &ns);
    };

    class gpio_gate_responder : public ka::gate_responder {
    public:
        using ka::gate_responder::gate_responder;

        void on_authentication_success(ka::identity const &) override;
    };

}// namespace ka

namespace mlab {
    bin_data &operator<<(bin_data &bd, ka::gpio_responder_config const &grc);
    bin_stream &operator>>(bin_stream &s, ka::gpio_responder_config &grc);
}// namespace mlab

#endif//KEYCARD_ACCESS_GPIO_AUTH_RESPONDER_HPP
