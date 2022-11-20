#include <ka/keypair.hpp>
#include <unity.h>

using namespace ka;

static const unsigned char plaintext[] = "The quick brown fox jumps over the lazy dog";

void test_encrypt_decrypt() {
    const mlab::bin_data message = mlab::bin_data::chain(plaintext);
    mlab::bin_data buffer = message;

    key_pair k1, k2;
    k1.generate();
    k2.generate();

    TEST_ASSERT(k1.is_valid());
    TEST_ASSERT(k2.is_valid());

    TEST_ASSERT(k1.encrypt_for(k2, buffer));
    TEST_ASSERT(k2.decrypt_from(k1, buffer));

    TEST_ASSERT_EQUAL(buffer.size(), message.size());
    TEST_ASSERT_EQUAL_HEX8_ARRAY(message.data(), buffer.data(), std::min(message.size(), buffer.size()));
}

void test_keys() {
    key_pair k;
    TEST_ASSERT(not k.is_valid());

    k.generate();
    TEST_ASSERT(k.is_valid());

    key_pair k2{k.raw_sk()};
    TEST_ASSERT(k2.is_valid());
    TEST_ASSERT(k.raw_pk() == k2.raw_pk());
}

extern "C" void app_main() {
    UNITY_BEGIN();

    RUN_TEST(test_keys);
    RUN_TEST(test_encrypt_decrypt);

    UNITY_END();
}