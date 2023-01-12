//
// Created by spak on 10/2/22.
//

#ifndef KEYCARDACCESS_CONFIG_HPP
#define KEYCARDACCESS_CONFIG_HPP

#include <driver/uart.h>
#include <hal/gpio_types.h>
#include <ka/data.hpp>
#include <ka/key_pair.hpp>
#include <string>

namespace ka {
    namespace nvs {
        class const_namespc;
        class partition;
    }

    class gate_config {
        gate_id _id = std::numeric_limits<gate_id>::max();
        std::string _desc;
        key_pair _kp;
        pub_key _prog_pk;

        [[nodiscard]] bool try_load_key_pair(mlab::bin_data const &data);
        [[nodiscard]] bool try_load_programmer_key(mlab::bin_data const &data);
    public:
        gate_config() = default;
        gate_config(gate_config &&) noexcept = default;
        gate_config &operator=(gate_config &&) noexcept = default;

        [[nodiscard]] inline bool is_configured() const;
        [[nodiscard]] inline key_pair keys() const;
        [[nodiscard]] inline pub_key programmer_pub_key() const;
        [[nodiscard]] inline std::string description() const;
        [[nodiscard]] inline gate_id id() const;

        [[nodiscard]] static gate_config load_from_nvs(nvs::partition &partition);
        static void save_to_nvs(nvs::partition &partition, gate_config const &cfg);
        [[nodiscard]] static gate_config generate();
        static void clear_nvs(nvs::partition &partition);
    };

    namespace pinout {
#ifndef PN532_SERIAL_RX
        static constexpr gpio_num_t pn532_hsu_rx = GPIO_NUM_NC;
#else
        static constexpr gpio_num_t pn532_hsu_rx = static_cast<gpio_num_t>(PN532_SERIAL_RX);
#endif

#ifndef PN532_SERIAL_TX
        static constexpr gpio_num_t pn532_hsu_tx = GPIO_NUM_NC;
#else
        static constexpr gpio_num_t pn532_hsu_tx = static_cast<gpio_num_t>(PN532_SERIAL_TX);
#endif

        static constexpr uart_config_t uart_config = {
                .baud_rate = 115200,
                .data_bits = UART_DATA_8_BITS,
                .parity = UART_PARITY_DISABLE,
                .stop_bits = UART_STOP_BITS_1,
                .flow_ctrl = UART_HW_FLOWCTRL_DISABLE,
                .rx_flow_ctrl_thresh = 122,
                .source_clk = UART_SCLK_REF_TICK};

        static constexpr uart_port_t uart_port = UART_NUM_1;

        static_assert(pn532_hsu_rx > GPIO_NUM_NC and pn532_hsu_rx < GPIO_NUM_MAX, "You must define PN532_SERIAL_RX to be a valid GPIO pin.");
        static_assert(pn532_hsu_tx > GPIO_NUM_NC and pn532_hsu_tx < GPIO_NUM_MAX, "You must define PN532_SERIAL_TX to be a valid GPIO pin.");
    }
}// namespace ka


namespace ka {
    bool gate_config::is_configured() const {
        return _id != std::numeric_limits<gate_id>::max();
    }
    key_pair gate_config::keys() const {
        return _kp;
    }
    pub_key gate_config::programmer_pub_key() const {
        return _prog_pk;
    }
    std::string gate_config::description() const {
        return _desc;
    }
    gate_id gate_config::id() const {
        return _id;
    }
}
#endif//KEYCARDACCESS_CONFIG_HPP
