//
// Created by spak on 7/6/23.
//

#include <catch/catch.hpp>
#include <ka/key_pair.hpp>
#include <ka/nvs.hpp>
#include <mlab/strutils.hpp>


namespace ut {

    TEST_CASE("0000 Encrypt Decrypt") {
        const mlab::bin_data message = mlab::data_from_string("The quick brown fox jumps over the lazy dog");
        mlab::bin_data buffer = message;

        ka::key_pair k1, k2;
        k1.generate_random();
        k2.generate_random();

        CHECK(k1.is_valid());
        CHECK(k2.is_valid());

        CHECK(k1.encrypt_for(k2, buffer));
        CHECK(k2.decrypt_from(k1, buffer));

        CHECK(buffer == message);

        CHECK(k1.encrypt_for(k2, buffer));
        mlab::bin_data test_buffer = message;

        CHECK(k1.blind_check_ciphertext(k2, test_buffer, buffer));

        auto bd = k1.save_encrypted("");
        auto k3 = ka::key_pair::load_encrypted(bd, "");

        CHECK(k3 == k1);

        bd = k1.save_encrypted("foobar");
        k3 = ka::key_pair::load_encrypted(bd, "foobar");

        CHECK(k3 == k1);
    }

    TEST_CASE("0001 Keys") {
        ka::key_pair k;
        CHECK(not k.is_valid());

        k.generate_random();
        CHECK(k.is_valid());

        ka::key_pair const k2{k.raw_sk()};
        CHECK(k2.is_valid());
        CHECK(k == k2);
    }

    TEST_CASE("0002 NVS") {
        // Make sure nvs is initialized
        auto &nvs = ka::nvs::instance();

        auto part = nvs.open_partition(NVS_DEFAULT_PART_NAME, false);
        REQUIRE(part != nullptr);
        auto ns = part->open_namespc("ka");
        REQUIRE(ns != nullptr);
        ns->erase("foo");
        CHECK(ns->commit());
        auto r_num = ns->get<std::uint32_t>("foo");
        CHECK(not r_num);
        CHECK(ns->set<std::uint32_t>("foo", 0x42));
        CHECK(ns->commit());
        r_num = ns->get<std::uint32_t>("foo");
        CHECKED_IF_FAIL(r_num) {
            CHECK(*r_num == 0x42);
        }
        const auto stats = part->get_stats();
        ESP_LOGI("UT", "nvs     free entries: %d", stats.free_entries);
        ESP_LOGI("UT", "nvs  namespace count: %d", stats.namespace_count);
        ESP_LOGI("UT", "nvs     used entries: %d", stats.used_entries);
        ESP_LOGI("UT", "nvs    total entries: %d", stats.total_entries);
        ESP_LOGI("UT", "nvs::ka used entries: %d", ns->used_entries());
        CHECK(ns->erase("foo"));
        CHECK(ns->commit());
        r_num = ns->get<std::uint32_t>("foo");
        CHECK(not r_num);

        const auto sample_data = mlab::bin_data{0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0xa, 0xb, 0xc, 0xd, 0xe, 0xf};
        CHECK(ns->set("foo", sample_data));
        CHECK(ns->commit());
        auto r_data = ns->get<mlab::bin_data>("foo");
        CHECK(r_data);
        CHECK(ns->erase("foo"));
        CHECK(ns->commit());

        CHECK(*r_data == sample_data);
    }
}// namespace ut