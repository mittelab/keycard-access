//
// Created by spak on 1/4/23.
//

#ifndef KEYCARD_ACCESS_PINOUT_HPP
#define KEYCARD_ACCESS_PINOUT_HPP

#include <driver/gpio.h>
#include <driver/uart.h>

namespace ut::pinout {

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
}// namespace ut::pinout

#endif//KEYCARD_ACCESS_PINOUT_HPP