//
// Created by spak on 7/6/23.
//

#ifndef KEYCARD_ACCESS_TEST_BASIC_HPP
#define KEYCARD_ACCESS_TEST_BASIC_HPP

#ifndef PN532_I0
    static constexpr gpio_num_t pn532_cicd_i0 = GPIO_NUM_NC;
#else
    static constexpr gpio_num_t pn532_cicd_i0 = static_cast<gpio_num_t>(PN532_I0);
#endif

#ifndef PN532_I1
    static constexpr gpio_num_t pn532_cicd_i1 = GPIO_NUM_NC;
#else
    static constexpr gpio_num_t pn532_cicd_i1 = static_cast<gpio_num_t>(PN532_I1);
#endif

#ifndef PN532_RSTN
    static constexpr gpio_num_t pn532_cicd_rstn = GPIO_NUM_NC;
#else
    static constexpr gpio_num_t pn532_cicd_rstn = static_cast<gpio_num_t>(PN532_RSTN);
#endif

#ifdef SPOOKY_CI_CD_MACHINE
    static constexpr bool supports_cicd_machine = true;
#else
    static constexpr bool supports_cicd_machine = false;
#endif

namespace ut {
    void test_encrypt_decrypt();
    void test_keys();
    void test_nvs();
}// namespace ut

#endif//KEYCARD_ACCESS_TEST_BASIC_HPP
