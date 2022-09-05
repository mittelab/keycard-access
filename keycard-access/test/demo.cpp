#include <unity.h>

void dummy_test() {
    TEST_ASSERT_EQUAL(42, 42);
}

extern "C" void app_main() {
    UNITY_BEGIN();

    RUN_TEST(dummy_test);

    UNITY_END();
}