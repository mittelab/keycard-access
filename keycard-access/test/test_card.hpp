//
// Created by spak on 7/6/23.
//

#ifndef KEYCARD_ACCESS_TEST_CARD_HPP
#define KEYCARD_ACCESS_TEST_CARD_HPP

namespace ut {

    struct controller_test_fixture {
        controller_test_fixture();

        controller_test_fixture(controller_test_fixture &&) = delete;
        controller_test_fixture(controller_test_fixture const &) = delete;

        explicit operator bool() const;

        /**
         * @addtogroup Test
         * To be called with an active instance.
         * @{
         */
        static void test_wake_channel();
        static void test_controller();
        /**
         * @}
         */

        ~controller_test_fixture();
    };

    struct token_test_fixture {
        token_test_fixture();

        token_test_fixture(token_test_fixture &&) = delete;
        token_test_fixture(token_test_fixture const &) = delete;

        explicit operator bool() const;

        ~token_test_fixture();

        /**
         * @addtogroup Test
         * To be called with an active instance.
         * @{
         */
        static void test_tag_reset_root_key_and_format();
        static void test_root_ops();
        static void test_app_ops();
        static void test_file_ops();
        static void test_regular_flow();
        static void test_cleanup();
        /**
         * @}
         */
    };
}// namespace ut

#endif//KEYCARD_ACCESS_TEST_CARD_HPP
