//
// Created by spak on 7/6/23.
//

#ifndef KEYCARD_ACCESS_TEST_BUNDLE_HPP
#define KEYCARD_ACCESS_TEST_BUNDLE_HPP

#include <ka/gate.hpp>
#include <ka/keymaker.hpp>

namespace ut {
    using ka::operator""_g;

    struct test_bundle {
        ka::key_pair km_kp{{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
                            0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f}};

        ka::keymaker km{km_kp};

        ka::gate_base_key g0_bk{0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f,
                                0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4a, 0x4b, 0x4c, 0x4d, 0x4e, 0x4f};

        ka::gate g0{ka::key_pair{{0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
                                  0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f}},
                    0_g, km_kp.drop_secret_key(), g0_bk};

        ka::gate_base_key g13_bk{0x70, 0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77, 0x78, 0x79, 0x7a, 0x7b, 0x7c, 0x7d, 0x7e, 0x7f,
                                 0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88, 0x89, 0x8a, 0x8b, 0x8c, 0x8d, 0x8e, 0x8f};

        ka::gate g13{ka::key_pair{{0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58, 0x59, 0x5a, 0x5b, 0x5c, 0x5d, 0x5e, 0x5f,
                                   0x60, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69, 0x6a, 0x6b, 0x6c, 0x6d, 0x6e, 0x6f}},
                     13_g,
                     km_kp.drop_secret_key(),
                     g13_bk};

        ka::gate_config g0_cfg{ka::gate_credentials{g0.keys().drop_secret_key(), g0_bk}, 0_g};

        ka::gate_config g13_cfg{ka::gate_credentials{g13.keys().drop_secret_key(), g13_bk}, 13_g};

        ka::gate g0_uncfg{g0.keys()};

        ka::identity id{{}, "Test user", "Test deployer"};

    } const bundle{};

    namespace sec_keys {
        /**
         * @addtogroup Secondary keys
         * @note These keys are those used in testing `libSpookyAction`, we will include them so that if tests
         * fail mid-way we can recover.
         * @{
         */
        constexpr std::uint8_t version = 0x10;
        constexpr std::array<std::uint8_t, 8> des = {0x0, 0x2, 0x4, 0x6, 0x8, 0xa, 0xc, 0xe};
        constexpr std::array<std::uint8_t, 16> des3_2k = {0x0, 0x2, 0x4, 0x6, 0x8, 0xa, 0xc, 0xe, 0x10, 0x12, 0x14, 0x16, 0x18, 0x1a, 0x1c, 0x1e};
        constexpr std::array<std::uint8_t, 24> des3_3k = {0x0, 0x2, 0x4, 0x6, 0x8, 0xa, 0xc, 0xe, 0x10, 0x12, 0x14, 0x16, 0x18, 0x1a, 0x1c, 0x1e, 0x20, 0x22, 0x24, 0x26, 0x28, 0x2a, 0x2c, 0x2e};
        constexpr std::array<std::uint8_t, 16> aes = {0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0xa, 0xb, 0xc, 0xd, 0xe, 0xf};
        /**
         * @}
         */
    }// namespace sec_keys

}// namespace ut
#endif//KEYCARD_ACCESS_TEST_BUNDLE_HPP
