#include <ka/keypair.hpp>
#include <unity.h>

using namespace ka;

void test_encrypt_decrypt() {
    static const unsigned char plaintext[] = "The quick brown fox jumps over the lazy dog";
    const mlab::bin_data txt_data = mlab::bin_data::chain(plaintext);

    keypair k;
    TEST_ASSERT(k.generate());

    const auto enc_res = k.encrypt(txt_data);
    TEST_ASSERT(enc_res);
    const auto dec_res = k.decrypt(*enc_res);
    TEST_ASSERT(dec_res);
    TEST_ASSERT_EQUAL(dec_res->size(), txt_data.size());
    TEST_ASSERT_EQUAL_HEX8_ARRAY(txt_data.data(), dec_res->data(), std::min(txt_data.size(), dec_res->size()));
}

void test_keys() {
    keypair k;
    TEST_ASSERT(not k.has_private());
    TEST_ASSERT(not k.has_public());

    k.generate();

    TEST_ASSERT(k.has_private());
    TEST_ASSERT(k.has_public());
    TEST_ASSERT(k.has_matching_public_private());

    const auto k_dump_sec = k.export_key(true);
    const auto k_dump_pub = k.export_key(false);

    TEST_ASSERT(not k_dump_sec.empty());
    TEST_ASSERT(not k_dump_pub.empty());

    keypair k_pub;
    keypair k_sec;

    TEST_ASSERT(not k_pub.has_private());
    TEST_ASSERT(not k_pub.has_matching_public_private());

    TEST_ASSERT(k_pub.import_key(k_dump_pub));
    TEST_ASSERT(k_sec.import_key(k_dump_sec));

    TEST_ASSERT(k_pub.has_public());
    TEST_ASSERT(not k_pub.has_private());
    TEST_ASSERT(not k_pub.has_matching_public_private());

    TEST_ASSERT(k_sec.has_public());
    TEST_ASSERT(k_sec.has_private());

    keypair k_copy;
    TEST_ASSERT(k_copy.import_key(k_dump_pub));
    TEST_ASSERT(k_copy.has_public());
    TEST_ASSERT(not k_copy.has_private());
    TEST_ASSERT(not k_copy.has_matching_public_private());

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
    RUN_TEST(test_encrypt_decrypt);

    UNITY_END();
}