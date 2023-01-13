#include <desfire/esp32/cipher_provider.hpp>
#include <desfire/esp32/utils.hpp>
#include <desfire/tag.hpp>
#include <ka/config.hpp>
#include <ka/desfire_fs.hpp>
#include <ka/key_pair.hpp>
#include <ka/member_token.hpp>
#include <ka/nvs.hpp>
#include <ka/ticket.hpp>
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
        k1.generate_random();
        k2.generate_random();

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

        k.generate_random();
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

        [[nodiscard]] key_pair &test_key_pair() {
            static key_pair _kp{{
                    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
                    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f
            }};
            if (not _kp.is_valid()) {
                ESP_LOGE("TEST", "Chosen fixed key pair is invalid.");
                std::abort();
            }
            return _kp;
        }

        using namespace ::desfire::esp32;
    }// namespace

    template <class Result>
    [[nodiscard]] bool passthru_set(bool &dest, Result const &res);

    template <class Result>
    [[nodiscard]] bool passthru_and(bool &dest, Result const &res);

    template <bool B, class Result>
    [[nodiscard]] bool ok_and(Result const &res);

    struct {
        std::unique_ptr<pn532::esp32::hsu_channel> channel;
        std::unique_ptr<pn532::controller> controller;
        bool did_pass_controller_test = false;
        token_id nfc_id{};
        std::unique_ptr<desfire::tag> tag;
        bool warn_before_formatting = true;
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
        const auto r_info = instance.tag->get_info();
        const desfire::any_key default_k{desfire::cipher_type::des};
        const std::array<desfire::any_key, 10> keys_to_test{
                default_k,
                test_key_pair().derive_token_root_key(instance.nfc_id),
                r_info ? test_key_pair().derive_token_root_key(r_info->serial_no) : default_k,
                desfire::any_key{desfire::cipher_type::des3_2k},
                desfire::any_key{desfire::cipher_type::des3_3k},
                desfire::any_key{desfire::cipher_type::aes128},
                desfire::any_key{desfire::cipher_type::des, mlab::make_range(secondary_des_key), 0, secondary_keys_version},
                desfire::any_key{desfire::cipher_type::des3_2k, mlab::make_range(secondary_des3_2k_key), 0, secondary_keys_version},
                desfire::any_key{desfire::cipher_type::des3_3k, mlab::make_range(secondary_des3_3k_key), 0, secondary_keys_version},
                desfire::any_key{desfire::cipher_type::aes128, mlab::make_range(secondary_aes_key), 0, secondary_keys_version}};
        // Ok now attempt to retrieve the root keys among those we usually use for testing.
        ESP_LOGI("TEST", "Attempt to recover the root key.");
        TEST_ASSERT(instance.tag->select_application());
        for (auto const &key : keys_to_test) {
            auto suppress = suppress_log{DESFIRE_DEFAULT_LOG_PREFIX};
            if (instance.tag->authenticate(key)) {
                suppress.restore();
                ESP_LOGI("TEST", "Found the right key, changing to default.");
                TEST_ASSERT(instance.tag->change_key(default_k));
                TEST_ASSERT(instance.tag->authenticate(default_k));
                if (instance.warn_before_formatting) {
                    ESP_LOGW("TEST", "We will now format the tag. Remove it if you hold your data dear!");
                    for (unsigned i = 5; i > 0; --i) {
                        ESP_LOGW("TEST", "Formatting in %d seconds...", i);
                        std::this_thread::sleep_for(1s);
                    }
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
        auto r_id = token.get_id();
        TEST_ASSERT(r_id);
        if (not r_id) {
            return;
        }
        TEST_ASSERT(token.setup_root(test_key_pair().derive_token_root_key(*r_id)));
        TEST_ASSERT(token.setup_mad({*r_id, ut::test_holder, ut::test_publisher}));

        // Mad must be readable without auth
        TEST_ASSERT(instance.tag->select_application());
        auto suppress = suppress_log{DESFIRE_DEFAULT_LOG_PREFIX};
        // CardUID is not accessible without auth
        TEST_ASSERT_FALSE(instance.tag->get_card_uid());
        suppress.restore();
        TEST_ASSERT(instance.tag->select_application());

        // But the id from get_version must be
        r_id = token.get_id();
        const auto r_mad_version = token.get_mad_version();
        const auto r_holder = token.get_holder();
        const auto r_publisher = token.get_publisher();

        TEST_ASSERT(r_id);
        TEST_ASSERT(r_mad_version);
        TEST_ASSERT(r_holder);
        TEST_ASSERT(r_publisher);

        if (r_mad_version) {
            TEST_ASSERT_EQUAL(*r_mad_version, 0x03);
        }
        if (r_holder) {
            TEST_ASSERT(*r_holder == test_holder);
        }
        if (r_publisher) {
            TEST_ASSERT(*r_publisher == test_publisher);
        }
        if (r_id) {
            // Should be sensible enough
            TEST_ASSERT(*r_id == instance.nfc_id);
        }

        // Check that the mad application is not trivially writable
        TEST_ASSERT(instance.tag->select_application(member_token::mad_aid));
        suppress.suppress();
        TEST_ASSERT_FALSE(instance.tag->create_file(0x00, desfire::file_settings<desfire::file_type::value>{}));
    }

    void test_enroll_and_auth() {
        TEST_ASSERT(instance.tag != nullptr);
        if (instance.tag == nullptr) {
            return;
        }

        member_token token{*instance.tag};
        constexpr gate_id gid = 0x00;

        const auto r_id = token.get_id();
        TEST_ASSERT(r_id);
        if (not r_id) {
            return;
        }

        auto suppress = suppress_log{DESFIRE_DEFAULT_LOG_PREFIX};
        TEST_ASSERT(token.try_set_root_key(test_key_pair().derive_token_root_key(*r_id)));
        suppress.restore();

        TEST_ASSERT(token.get_identity());
        auto r_status = token.get_gate_status(gid);
        TEST_ASSERT(r_status);
        TEST_ASSERT_EQUAL(*r_status, gate_status::unknown);

        const auto r_enroll_ticket = token.install_enroll_ticket(gid);
        TEST_ASSERT(r_enroll_ticket);

        r_status = token.get_gate_status(gid);
        TEST_ASSERT(r_status);
        TEST_ASSERT_EQUAL(*r_status, gate_status::enrolled);
        TEST_ASSERT(ok_and<true>(token.verify_enroll_ticket(gid, *r_enroll_ticket)));

        const auto auth_ticket = ticket::generate(0);

        suppress = suppress_log{DESFIRE_DEFAULT_LOG_PREFIX, DESFIRE_FS_DEFAULT_LOG_PREFIX, "KA"};
        TEST_ASSERT_FALSE(token.verify_auth_ticket(gid, auth_ticket));
        suppress.restore();
        TEST_ASSERT(token.switch_enroll_to_auth_ticket(gid, *r_enroll_ticket, auth_ticket));
        suppress.suppress();
        TEST_ASSERT_FALSE(token.verify_enroll_ticket(gid, *r_enroll_ticket));
        suppress.restore();

        r_status = token.get_gate_status(gid);
        TEST_ASSERT(r_status);
        TEST_ASSERT_EQUAL(*r_status, gate_status::auth_ready);

        TEST_ASSERT(ok_and<true>(token.verify_auth_ticket(gid, auth_ticket)));

        TEST_ASSERT(token.authenticate_legacy(gid, auth_ticket));

        // Check that it can be authenticated also with a member token with an unknown password
        {
            member_token token_no_root{*instance.tag};
            TEST_ASSERT(token_no_root.tag().select_application());
            TEST_ASSERT(token_no_root.authenticate_legacy(gid, auth_ticket));
        }

        TEST_ASSERT(token.unlock_root());
        TEST_ASSERT(desfire::fs::delete_app_if_exists(token.tag(), gate::id_to_app_id(gid)));

        r_status = token.get_gate_status(gid);
        TEST_ASSERT(r_status);
        TEST_ASSERT_EQUAL(*r_status, gate_status::unknown);

        suppress = suppress_log{DESFIRE_DEFAULT_LOG_PREFIX, DESFIRE_FS_DEFAULT_LOG_PREFIX, "KA"};
        TEST_ASSERT_FALSE(token.authenticate_legacy(gid, auth_ticket));
    }

    void test_ticket() {
        TEST_ASSERT(instance.tag != nullptr);
        if (instance.tag == nullptr) {
            return;
        }

        member_token token{*instance.tag};

        const auto r_id = token.get_id();
        TEST_ASSERT(r_id);
        if (not r_id) {
            return;
        }

        auto suppress = suppress_log{DESFIRE_DEFAULT_LOG_PREFIX};
        TEST_ASSERT(token.try_set_root_key(test_key_pair().derive_token_root_key(*r_id)));
        suppress.restore();

        TEST_ASSERT(token.unlock_root());

        const auto aid = desfire::app_id{0x11, 0x12, 0x13};
        const auto fid = desfire::file_id{0x00};
        const auto app_master_key = key_type{0x00, desfire::random_oracle{esp_fill_random}};

        TEST_ASSERT(desfire::fs::delete_app_if_exists(token.tag(), aid));
        TEST_ASSERT(desfire::fs::create_app(token.tag(), aid, app_master_key, desfire::key_rights{}, 1));

        const auto t = ticket{0x01 /* use key no 1 */};

        TEST_ASSERT(t.install(token.tag(), fid, "foo bar"));

        suppress.suppress();
        // This should not be readable at this point
        TEST_ASSERT_FALSE(token.tag().read_data(fid, desfire::trust_card));
        suppress.restore();

        // Neither with the app master key
        TEST_ASSERT(desfire::fs::login_app(token.tag(), aid, app_master_key));
        suppress.suppress();
        TEST_ASSERT_FALSE(token.tag().read_data(fid, desfire::trust_card));
        suppress.restore();

        // Nor changeable with the app master key
        TEST_ASSERT(desfire::fs::login_app(token.tag(), aid, app_master_key));
        suppress.suppress();
        TEST_ASSERT_FALSE(token.tag().change_file_settings(fid, {desfire::file_security::none, desfire::access_rights{}}, desfire::trust_card));
        suppress.restore();

        // Need the to be on the app to be able to verify it
        TEST_ASSERT(desfire::fs::login_app(token.tag(), aid, app_master_key));
        TEST_ASSERT(ok_and<true>(t.verify(token.tag(), fid, "foo bar")));

        suppress.suppress();
        // Should not work outside the app
        TEST_ASSERT(token.unlock_root());
        suppress.restore();
        suppress = suppress_log{DESFIRE_DEFAULT_LOG_PREFIX, "KA"};
        TEST_ASSERT_FALSE(t.verify(token.tag(), fid, "foo bar"));
        suppress.restore();

        // Should be repeatable if not deleted
        TEST_ASSERT(desfire::fs::login_app(token.tag(), aid, app_master_key));
        TEST_ASSERT(ok_and<false>(t.verify(token.tag(), fid, "foo bar baz")));

        TEST_ASSERT(desfire::fs::login_app(token.tag(), aid, app_master_key));
        TEST_ASSERT(t.clear(token.tag(), fid));

        suppress.suppress();
        TEST_ASSERT(desfire::fs::login_app(token.tag(), aid, app_master_key));
        TEST_ASSERT_FALSE(t.verify(token.tag(), fid, "foo bar"));
        suppress.restore();

        TEST_ASSERT(ok_and<false>(desfire::fs::does_file_exist(token.tag(), fid)));

        // Ok delete app
        TEST_ASSERT(token.unlock_root());
        TEST_ASSERT(desfire::fs::delete_app_if_exists(token.tag(), aid));
    }

    void test_nvs() {
        nvs::nvs root{};
        auto part = root.open_partition(NVS_DEFAULT_PART_NAME, false);
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
        ESP_LOGI("TEST", "nvs     free entries: %d", stats.free_entries);
        ESP_LOGI("TEST", "nvs  namespace count: %d", stats.namespace_count);
        ESP_LOGI("TEST", "nvs     used entries: %d", stats.used_entries);
        ESP_LOGI("TEST", "nvs    total entries: %d", stats.total_entries);
        ESP_LOGI("TEST", "nvs::ka used entries: %d", ns->used_entries());
        TEST_ASSERT(ns->erase("foo"));
        TEST_ASSERT(ns->commit());
        r_num = ns->get<std::uint32_t>("foo");
        TEST_ASSERT_FALSE(r_num);

    }
}// namespace ut

extern "C" void app_main() {
    UNITY_BEGIN();

    RUN_TEST(ut::test_keys);
    RUN_TEST(ut::test_nvs);
    RUN_TEST(ut::test_encrypt_decrypt);

    ESP_LOGI("TEST", "Attempting to set up a PN532 on pins %d, %d", pinout::pn532_hsu_rx, pinout::pn532_hsu_tx);

    ut::instance.channel = std::make_unique<pn532::esp32::hsu_channel>(
            pinout::uart_port, pinout::uart_config, pinout::pn532_hsu_tx, pinout::pn532_hsu_rx);
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
        RUN_TEST(ut::test_ticket);
        RUN_TEST(ut::test_enroll_and_auth);

        // Always conclude with a format test so that it leaves the test suite clean
        ut::instance.warn_before_formatting = false;
        RUN_TEST(ut::test_tag_reset_root_key_and_format);
    }

    UNITY_END();
}

namespace ut {

    template <class Result>
    bool passthru_set(bool &dest, Result const &res) {
        if constexpr (std::is_same_v<Result, bool>) {
            dest = res;
        } else if constexpr (std::is_same_v<decltype(*res), bool>) {
            dest = res and *res;
        } else {
            dest = bool(res);
        }
        return dest;
    }

    template <class Result>
    bool passthru_and(bool &dest, Result const &res) {
        if constexpr (std::is_same_v<Result, bool>) {
            dest &= res;
        } else if constexpr (std::is_same_v<decltype(*res), bool>) {
            dest &= res and *res;
        } else {
            dest &= bool(res);
        }
        return dest;
    }


    template <bool B, class Result>
    bool ok_and(Result const &res) {
        return res and *res == B;
    }

}// namespace ut