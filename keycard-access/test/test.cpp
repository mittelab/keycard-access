#include <ka/keys.hpp>
#include <unity.h>

using namespace ka;

void test_keys() {
    keypair k;
    TEST_ASSERT(not k.has_private());
    TEST_ASSERT(not k.has_public());

    k.generate();

    TEST_ASSERT(k.has_private());
    TEST_ASSERT(k.has_public());

    const auto k_dump_sec = k.export_key(true);
    const auto k_dump_pub = k.export_key(false);

    TEST_ASSERT(not k_dump_sec.empty());
    TEST_ASSERT(not k_dump_pub.empty());

    keypair k_pub;
    keypair k_sec;

    TEST_ASSERT(k_pub.import_key(k_dump_pub, false));
    TEST_ASSERT(k_sec.import_key(k_dump_sec, true));

    TEST_ASSERT(k_pub.has_public());
    TEST_ASSERT(not k_pub.has_private());

    TEST_ASSERT(k_sec.has_public());
    TEST_ASSERT(k_sec.has_private());

    keypair k_copy;
    TEST_ASSERT(k_copy.import_key(k_dump_pub));
    TEST_ASSERT(k_copy.has_public());
    TEST_ASSERT(not k_copy.has_private());

    TEST_ASSERT(k_copy.import_key(k_dump_sec));
    TEST_ASSERT(k_copy.has_public());
    TEST_ASSERT(k_copy.has_private());

    const auto k_dump_sec_copy = k_sec.export_key(true);
    const auto k_dump_pub_copy = k_pub.export_key(false);

    TEST_ASSERT_EQUAL(k_dump_sec_copy.size(), k_dump_sec.size());
    TEST_ASSERT_EQUAL(k_dump_pub_copy.size(), k_dump_pub.size());

    TEST_ASSERT_EQUAL_HEX8_ARRAY(k_dump_sec_copy.data(), k_dump_sec.data(), std::min(k_dump_sec_copy.size(), k_dump_sec.size()));
    TEST_ASSERT_EQUAL_HEX8_ARRAY(k_dump_pub_copy.data(), k_dump_pub.data(), std::min(k_dump_pub_copy.size(), k_dump_pub.size()));
}

extern "C" void app_main() {
    UNITY_BEGIN();

    RUN_TEST(test_keys);

    UNITY_END();
}