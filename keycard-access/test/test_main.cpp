#include "test_basic.hpp"
#include "test_card.hpp"
#include "test_p2p.hpp"
#include <unity.h>

extern "C" void app_main() {
    UNITY_BEGIN();

    RUN_TEST(ut::test_keys);
    RUN_TEST(ut::test_nvs);
    RUN_TEST(ut::test_encrypt_decrypt);

    RUN_TEST(ut::test_p2p_comm);
    RUN_TEST(ut::test_p2p_registration);
    RUN_TEST(ut::test_rpc);
    RUN_TEST(ut::test_rpc_gate);
    RUN_TEST(ut::test_rpc_registration);

    {
        ut::controller_test_fixture ctrl_fixture;
        RUN_TEST(ut::controller_test_fixture::test_wake_channel);
        RUN_TEST(ut::controller_test_fixture::test_controller);

        {
            ut::token_test_fixture token_fixture;
            RUN_TEST(ut::token_test_fixture::test_tag_reset_root_key_and_format);
            RUN_TEST(ut::token_test_fixture::test_root_ops);
            RUN_TEST(ut::token_test_fixture::test_app_ops);
            RUN_TEST(ut::token_test_fixture::test_file_ops);
            RUN_TEST(ut::token_test_fixture::test_regular_flow);
            RUN_TEST(ut::token_test_fixture::test_cleanup);
        }
    }

    UNITY_END();
}

namespace ut {


}// namespace ut