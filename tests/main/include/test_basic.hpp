//
// Created by spak on 7/6/23.
//

#ifndef KEYCARD_ACCESS_TEST_BASIC_HPP
#define KEYCARD_ACCESS_TEST_BASIC_HPP

namespace ut::pinout {
    static constexpr gpio_num_t pn532_hsu_rx = static_cast<gpio_num_t>(CONFIG_PN532_HSU_TX);
    static constexpr gpio_num_t pn532_hsu_tx = static_cast<gpio_num_t>(CONFIG_PN532_HSU_RX);
    static constexpr gpio_num_t pn532_cicd_i0 = static_cast<gpio_num_t>(CONFIG_PN532_I0);
    static constexpr gpio_num_t pn532_cicd_i1 = static_cast<gpio_num_t>(CONFIG_PN532_I1);
    static constexpr gpio_num_t pn532_cicd_rstn = static_cast<gpio_num_t>(CONFIG_PN532_RSTN);
}

#endif//KEYCARD_ACCESS_TEST_BASIC_HPP
