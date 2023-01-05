#include "pinout.hpp"
#include <desfire/esp32/cipher_provider.hpp>
#include <desfire/tag.hpp>
#include <ka/keypair.hpp>
#include <ka/member_token.hpp>
#include <pn532/controller.hpp>
#include <pn532/desfire_pcd.hpp>
#include <pn532/esp32/hsu.hpp>
#include <thread>
#include <unity.h>

using namespace ka;
using namespace std::chrono_literals;

static const unsigned char plaintext[] = "The quick brown fox jumps over the lazy dog";

namespace ut {

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

        key_pair const k2{k.raw_sk()};
        TEST_ASSERT(k2.is_valid());
        TEST_ASSERT(k.raw_pk() == k2.raw_pk());
    }

    namespace {
        /**
         * @addtogroup Secondary keys
         * @note These keys are those used in testing `libSpookyAction`, we will include them so that if tests
         * fail mid-way we can recover.
         * @{
         */
        constexpr std::uint8_t secondary_keys_version = 0x10;
        constexpr std::array<std::uint8_t, 8> secondary_des_key = {0x0, 0x2, 0x4, 0x6, 0x8, 0xa, 0xc, 0xe};
        constexpr std::array<std::uint8_t, 16> secondary_des3_2k_key = {0x0, 0x2, 0x4, 0x6, 0x8, 0xa, 0xc, 0xe, 0x10, 0x12, 0x14, 0x16, 0x18, 0x1a, 0x1c, 0x1e};
        constexpr std::array<std::uint8_t, 24> secondary_des3_3k_key = {0x0, 0x2, 0x4, 0x6, 0x8, 0xa, 0xc, 0xe, 0x10, 0x12, 0x14, 0x16, 0x18, 0x1a, 0x1c, 0x1e, 0x20, 0x22, 0x24, 0x26, 0x28, 0x2a, 0x2c, 0x2e};
        constexpr std::array<std::uint8_t, 16> secondary_aes_key = {0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0xa, 0xb, 0xc, 0xd, 0xe, 0xf};
        /**
         * @}
         */

        constexpr auto test_holder = "user";
        constexpr auto test_publisher = "Mittelab";
    }

    template <class Result>
    [[nodiscard]] bool passthru_set(bool &dest, Result const &res);

    template <class Result>
    [[nodiscard]] bool passthru_and(bool &dest, Result const &res);

    struct {
        std::unique_ptr<pn532::esp32::hsu_channel> channel;
        std::unique_ptr<pn532::controller> controller;
        bool did_pass_controller_test = false;
        member_token::id_t nfc_id{};
        std::unique_ptr<desfire::tag> tag;
    } instance{};

    void test_wake_channel() {
        TEST_ASSERT(instance.channel != nullptr);
        TEST_ASSERT(instance.controller != nullptr);
        if (instance.channel != nullptr) {
            TEST_ASSERT(instance.channel->wake());
            if (instance.controller != nullptr) {
                TEST_ASSERT(instance.controller->sam_configuration(pn532::sam_mode::normal, 1s));
            }
        }
    }

    void test_controller() {
        TEST_ASSERT(instance.controller != nullptr);
        if (instance.controller != nullptr) {
            TEST_ASSERT(passthru_set(instance.did_pass_controller_test,
                                     instance.controller->diagnose_comm_line()));
            TEST_ASSERT(passthru_and(instance.did_pass_controller_test,
                                     instance.controller->diagnose_self_antenna(pn532::low_current_thr::mA_25, pn532::high_current_thr::mA_150)));
        }
    }

    void test_tag_reset_root_key_and_format() {
        TEST_ASSERT(instance.tag != nullptr);
        if (instance.tag == nullptr) {
            return;
        }
        const desfire::any_key default_k{desfire::cipher_type::des};
        const std::array<desfire::any_key, 9> keys_to_test{
                default_k,
                member_token::get_default_root_key(instance.nfc_id),
                desfire::any_key{desfire::cipher_type::des3_2k},
                desfire::any_key{desfire::cipher_type::des3_3k},
                desfire::any_key{desfire::cipher_type::aes128},
                desfire::any_key{desfire::cipher_type::des, mlab::make_range(secondary_des_key), 0, secondary_keys_version},
                desfire::any_key{desfire::cipher_type::des3_2k, mlab::make_range(secondary_des3_2k_key), 0, secondary_keys_version},
                desfire::any_key{desfire::cipher_type::des3_3k, mlab::make_range(secondary_des3_3k_key), 0, secondary_keys_version},
                desfire::any_key{desfire::cipher_type::aes128, mlab::make_range(secondary_aes_key), 0, secondary_keys_version}
        };
        // Ok now attempt to retrieve the root keys among those we usually use for testing.
        ESP_LOGW("TEST", "Attempt to recover the root key (warnings/errors here are normal).");
        TEST_ASSERT(instance.tag->select_application());
        for (auto const &key : keys_to_test) {
            if (instance.tag->authenticate(key)) {
                ESP_LOGI("TEST", "Found the right key, changing to default.");
                TEST_ASSERT(instance.tag->change_key(default_k));
                TEST_ASSERT(instance.tag->authenticate(default_k));
                ESP_LOGW("TEST", "We will now format the tag. Remove it if you hold your data dear!");
                for (unsigned i = 5; i > 0; --i) {
                    ESP_LOGW("TEST", "Formatting in %d seconds...", i);
                    std::this_thread::sleep_for(1s);
                }
                TEST_ASSERT(instance.tag->format_picc());
                return;
            }
        }
        TEST_FAIL_MESSAGE("Unable to find the correct key.");
    }

    void test_mad() {
        TEST_ASSERT(instance.tag != nullptr);
        if (instance.tag == nullptr) {
            return;
        }

        member_token token{*instance.tag};
        TEST_ASSERT(token.setup_root_settings());
        TEST_ASSERT(token.setup_mad("user", "Mittelab"));
        TEST_ASSERT(token.unlock());

        // Mad must be readable without auth
        TEST_ASSERT(instance.tag->select_application());
        TEST_ASSERT_FALSE(instance.tag->get_card_uid());
        TEST_ASSERT(instance.tag->select_application());

        const auto r_mad_version = token.get_mad_version();
        const auto r_holder = token.get_holder();
        const auto r_publisher = token.get_publisher();

        TEST_ASSERT(r_mad_version);
        TEST_ASSERT(r_holder);
        TEST_ASSERT(r_publisher);

        if (r_mad_version) {
            TEST_ASSERT_EQUAL(*r_mad_version, member_token::mad_file_version);
        }
        if (r_holder) {
            TEST_ASSERT(*r_holder == test_holder);
        }
        if (r_publisher) {
            TEST_ASSERT(*r_publisher == test_publisher);
        }

        // Check that the mad application is not trivially writable
        TEST_ASSERT(instance.tag->select_application(member_token::mad_aid));
        TEST_ASSERT_FALSE(instance.tag->create_file(0x00, desfire::file_settings<desfire::file_type::value>{}));
    }
}

extern "C" void app_main() {
    UNITY_BEGIN();

    RUN_TEST(ut::test_keys);
    RUN_TEST(ut::test_encrypt_decrypt);

    ESP_LOGI("TEST", "Attempting to set up a PN532 on pins %d, %d", ut::pinout::pn532_hsu_rx, ut::pinout::pn532_hsu_tx);

    ut::instance.channel = std::make_unique<pn532::esp32::hsu_channel>(
            ut::pinout::uart_port, ut::pinout::uart_config, ut::pinout::pn532_hsu_tx, ut::pinout::pn532_hsu_rx);
    ut::instance.controller = std::make_unique<pn532::controller>(*ut::instance.channel);

    RUN_TEST(ut::test_wake_channel);
    RUN_TEST(ut::test_controller);

    if (ut::instance.did_pass_controller_test and ut::instance.controller != nullptr) {
        ESP_LOGI("TEST", "Attempting to scan for a Desfire card.");

        const auto r_scan = ut::instance.controller->initiator_list_passive_kbps106_typea(1, 5000ms);
        if (r_scan) {
            for (auto const &target : *r_scan) {
                ESP_LOGI("TEST", "Logical index %u; NFC ID:", target.logical_index);
                ESP_LOG_BUFFER_HEX_LEVEL("TEST", target.info.nfcid.data(), target.info.nfcid.size(), ESP_LOG_INFO);
                std::copy_n(std::begin(target.info.nfcid), ut::instance.nfc_id.size(), std::begin(ut::instance.nfc_id));
                ut::instance.tag = std::make_unique<desfire::tag>(
                        desfire::tag::make<desfire::esp32::default_cipher_provider>(
                                pn532::desfire_pcd{*ut::instance.controller, target.logical_index}));
                // We only need one
                break;
            }
        }

        if (ut::instance.tag == nullptr) {
            ESP_LOGE("TEST", "Could not find any tag!");
        }

        RUN_TEST(ut::test_tag_reset_root_key_and_format);
        RUN_TEST(ut::test_mad);

        // Always conclude with a format test so that it leaves the test suite clean
        RUN_TEST(ut::test_tag_reset_root_key_and_format);
    }

    UNITY_END();
}

namespace ut {

    template <class Result>
    [[nodiscard]] bool passthru_set(bool &dest, Result const &res) {
        if constexpr (std::is_same_v<Result, bool>) {
            dest = res;
        } else if constexpr(std::is_same_v<decltype(*res), bool>) {
            dest = res and *res;
        } else {
            dest = bool(res);
        }
        return dest;
    }

    template <class Result>
    [[nodiscard]] bool passthru_and(bool &dest, Result const &res) {
        if constexpr (std::is_same_v<Result, bool>) {
            dest &= res;
        } else if constexpr(std::is_same_v<decltype(*res), bool>) {
            dest &= res and *res;
        } else {
            dest &= bool(res);
        }
        return dest;
    }

}