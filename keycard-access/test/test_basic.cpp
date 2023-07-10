//
// Created by spak on 7/6/23.
//

#include "test_basic.hpp"
#include <ka/key_pair.hpp>
#include <ka/nvs.hpp>
#include <mlab/bin_data.hpp>
#include <mlab/strutils.hpp>
#include <nvs.h>
#include <unity.h>

namespace ut {

    void test_encrypt_decrypt() {
        const mlab::bin_data message = mlab::data_from_string("The quick brown fox jumps over the lazy dog");
        mlab::bin_data buffer = message;

        ka::key_pair k1, k2;
        k1.generate_random();
        k2.generate_random();

        TEST_ASSERT(k1.is_valid());
        TEST_ASSERT(k2.is_valid());

        TEST_ASSERT(k1.encrypt_for(k2, buffer));
        TEST_ASSERT(k2.decrypt_from(k1, buffer));

        TEST_ASSERT_EQUAL(buffer.size(), message.size());
        TEST_ASSERT_EQUAL_HEX8_ARRAY(message.data(), buffer.data(), std::min(message.size(), buffer.size()));

        TEST_ASSERT(k1.encrypt_for(k2, buffer));
        mlab::bin_data test_buffer = message;

        TEST_ASSERT(k1.blind_check_ciphertext(k2, test_buffer, buffer));
    }

    void test_keys() {
        ka::key_pair k;
        TEST_ASSERT(not k.is_valid());

        k.generate_random();
        TEST_ASSERT(k.is_valid());

        ka::key_pair const k2{k.raw_sk()};
        TEST_ASSERT(k2.is_valid());
        TEST_ASSERT(k == k2);
    }

    void test_nvs() {
        // Make sure nvs is initialized
        auto &nvs = ka::nvs::instance();

        auto part = nvs.open_partition(NVS_DEFAULT_PART_NAME, false);
        TEST_ASSERT(part != nullptr);
        auto ns = part->open_namespc("ka");
        TEST_ASSERT(ns != nullptr);
        ns->erase("foo");
        TEST_ASSERT(ns->commit());
        auto r_num = ns->get<std::uint32_t>("foo");
        TEST_ASSERT_FALSE(r_num);
        TEST_ASSERT(ns->set<std::uint32_t>("foo", 0x42));
        TEST_ASSERT(ns->commit());
        r_num = ns->get<std::uint32_t>("foo");
        TEST_ASSERT(r_num);
        if (r_num) {
            TEST_ASSERT_EQUAL(*r_num, 0x42);
        }
        const auto stats = part->get_stats();
        ESP_LOGI("UT", "nvs     free entries: %d", stats.free_entries);
        ESP_LOGI("UT", "nvs  namespace count: %d", stats.namespace_count);
        ESP_LOGI("UT", "nvs     used entries: %d", stats.used_entries);
        ESP_LOGI("UT", "nvs    total entries: %d", stats.total_entries);
        ESP_LOGI("UT", "nvs::ka used entries: %d", ns->used_entries());
        TEST_ASSERT(ns->erase("foo"));
        TEST_ASSERT(ns->commit());
        r_num = ns->get<std::uint32_t>("foo");
        TEST_ASSERT_FALSE(r_num);

        const auto sample_data = mlab::bin_data{0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0xa, 0xb, 0xc, 0xd, 0xe, 0xf};
        TEST_ASSERT(ns->set("foo", sample_data));
        TEST_ASSERT(ns->commit());
        auto r_data = ns->get<mlab::bin_data>("foo");
        TEST_ASSERT(r_data);
        TEST_ASSERT(ns->erase("foo"));
        TEST_ASSERT(ns->commit());

        TEST_ASSERT_EQUAL(r_data->size(), sample_data.size());
        TEST_ASSERT_EQUAL_HEX8_ARRAY(sample_data.data(), r_data->data(), sample_data.size());
    }
}// namespace ut