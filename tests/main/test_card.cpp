//
// Created by spak on 7/6/23.
//

#include "test_bundle.hpp"
#include <catch/catch.hpp>
#include <chrono>
#include <desfire/esp32/utils.hpp>
#include <desfire/fs.hpp>
#include <desfire/tag.hpp>
#include <driver/gpio.h>
#include <esp_log.h>
#include <ka/data.hpp>
#include <pn532/controller.hpp>
#include <pn532/esp32/hsu.hpp>
#include <thread>

#define TAG "UT"

using namespace std::chrono_literals;
using namespace mlab_literals;

namespace ut {
    namespace pinout {
        static constexpr gpio_num_t pn532_hsu_rx = static_cast<gpio_num_t>(CONFIG_PN532_HSU_TX);
        static constexpr gpio_num_t pn532_hsu_tx = static_cast<gpio_num_t>(CONFIG_PN532_HSU_RX);
#if CONFIG_PN532_CHANNEL_SELECTION
        static constexpr gpio_num_t pn532_cicd_i0 = static_cast<gpio_num_t>(CONFIG_PN532_I0);
        static constexpr gpio_num_t pn532_cicd_i1 = static_cast<gpio_num_t>(CONFIG_PN532_I1);
        static constexpr gpio_num_t pn532_cicd_rstn = static_cast<gpio_num_t>(CONFIG_PN532_RSTN);
#endif
    }// namespace pinout

    static constexpr uart_config_t uart_config = {
            .baud_rate = 115200,
            .data_bits = UART_DATA_8_BITS,
            .parity = UART_PARITY_DISABLE,
            .stop_bits = UART_STOP_BITS_1,
            .flow_ctrl = UART_HW_FLOWCTRL_DISABLE,
            .rx_flow_ctrl_thresh = 122,
            .source_clk = UART_SCLK_DEFAULT};

    template <bool B, class Result>
    [[nodiscard]] bool ok_and(Result const &res) {
        if constexpr (std::is_same_v<std::remove_const_t<std::remove_reference_t<decltype(*res)>>, bool>) {
            return res and *res == B;
        } else {
            return res and res->first == B;
        }
    }

    template <desfire::error E, class Result>
    [[nodiscard]] bool is_err(Result const &res) {
        if (res) {
            ESP_LOGE("UT", "The given result is not an error.");
            return false;
        } else if (res.error() != E) {
            ESP_LOGE("UT", "The given result is %s, not the expected %s.", to_string(res.error()), to_string(E));
            return false;
        }
        return true;
    }

    constexpr char boolalpha(bool b) {
        return b ? 'Y' : 'N';
    }

    void testinator_power_down(pn532::controller *ctrl = nullptr) {
        if (ctrl) {
            desfire::esp32::suppress_log suppress{PN532_TAG};
            ctrl->power_down({pn532::wakeup_source::i2c, pn532::wakeup_source::hsu, pn532::wakeup_source::spi});
        }
#if CONFIG_PN532_CHANNEL_SELECTION
        gpio_set_level(pinout::pn532_cicd_rstn, 0);
        std::this_thread::sleep_for(500ms);
#endif
    }

    void testinator_power_up() {
#if CONFIG_PN532_CHANNEL_SELECTION
        gpio_set_level(pinout::pn532_cicd_rstn, 1);
        std::this_thread::sleep_for(500ms);
#endif
    }

    void testinator_select_hsu() {
        /**
         * @note When running on the CI/CD machine, we need to make sure we are on HSU
         */
#if CONFIG_PN532_CHANNEL_SELECTION
        gpio_set_direction(pinout::pn532_cicd_rstn, GPIO_MODE_OUTPUT);
        gpio_set_direction(pinout::pn532_cicd_i0, GPIO_MODE_OUTPUT);
        gpio_set_direction(pinout::pn532_cicd_i1, GPIO_MODE_OUTPUT);
        // Power cycle the pn532
        testinator_power_down();
        // Change output to hsu
        gpio_set_level(pinout::pn532_cicd_i0, 0);
        gpio_set_level(pinout::pn532_cicd_i1, 0);
        testinator_power_up();
#endif
    }

    [[nodiscard]] bool testinator_attempt_activate(pn532::esp32::hsu_channel &chn, pn532::controller &ctrl) {
        for (std::size_t i = 0; i < 3; ++i) {
            testinator_power_up();
            if (chn.wake()) {
                if (const auto r = ctrl.sam_configuration(pn532::sam_mode::normal, 1s); r) {
                    return true;
                } else {
                    ESP_LOGW(TAG, "SAM not responding over HSU, retrying...");
                }
            } else {
                ESP_LOGW(TAG, "Unable to wake channel HSU, retrying...");
            }
            // Try to power down and retry
            testinator_power_down(&ctrl);
        }
        return false;
    }

    [[nodiscard]] bool card_recover_key_and_format(desfire::tag &tag, ka::token_id nfc_id, bool warn_before_formatting) {
        const auto r_info = tag.get_info();
        const desfire::any_key default_k{desfire::cipher_type::des};
        const ka::key_pair demo_key_pair{ka::pwhash, "foobar"};

        const std::array<desfire::any_key, 11> keys_to_test{
                default_k,
                bundle.km_kp.derive_token_root_key(nfc_id),
                r_info ? bundle.km_kp.derive_token_root_key(ka::token_id{r_info->serial_no}) : default_k,
                r_info ? demo_key_pair.derive_token_root_key(ka::token_id{r_info->serial_no}) : default_k,
                desfire::any_key{desfire::cipher_type::des3_2k},
                desfire::any_key{desfire::cipher_type::des3_3k},
                desfire::any_key{desfire::cipher_type::aes128},
                desfire::any_key{desfire::cipher_type::des, mlab::make_range(sec_keys::des), 0, sec_keys::version},
                desfire::any_key{desfire::cipher_type::des3_2k, mlab::make_range(sec_keys::des3_2k), 0, sec_keys::version},
                desfire::any_key{desfire::cipher_type::des3_3k, mlab::make_range(sec_keys::des3_3k), 0, sec_keys::version},
                desfire::any_key{desfire::cipher_type::aes128, mlab::make_range(sec_keys::aes), 0, sec_keys::version}};
        // Ok now attempt to retrieve the root keys among those we usually use for testing.
        ESP_LOGI("UT", "Attempt to recover the root key.");
        CHECK(tag.select_application());
        for (auto const &key : keys_to_test) {
            auto suppress = desfire::esp32::suppress_log{DESFIRE_LOG_PREFIX};
            if (tag.authenticate(key)) {
                suppress.restore();
                ESP_LOGI("UT", "Found the right key, changing to default.");
                CHECK(tag.change_key(default_k));
                CHECK(tag.authenticate(default_k));
                if (warn_before_formatting) {
                    ESP_LOGW("UT", "We will now format the tag. Remove it if you hold your data dear!");
                    for (unsigned i = 5; i > 0; --i) {
                        ESP_LOGW("UT", "Formatting in %d seconds...", i);
                        std::this_thread::sleep_for(1s);
                    }
                }
                CHECK(tag.format_picc());
                return true;
            }
        }
        return false;
    }

    TEST_CASE("0020 DESFire") {
        ESP_LOGI("UT", "Attempting to set up a PN532 on pins %d, %d", pinout::pn532_hsu_rx, pinout::pn532_hsu_tx);

        testinator_select_hsu();

        auto chn = std::make_shared<pn532::esp32::hsu_channel>(UART_NUM_1, uart_config, pinout::pn532_hsu_tx, pinout::pn532_hsu_rx);
        auto ctrl = std::make_shared<pn532::controller>(chn);

        REQUIRE(testinator_attempt_activate(*chn, *ctrl));
        REQUIRE(ctrl->diagnose_comm_line());
        REQUIRE(ctrl->diagnose_self_antenna(pn532::low_current_thr::mA_25, pn532::high_current_thr::mA_150));

        std::unique_ptr<desfire::tag> tag = nullptr;
        ka::token_id nfc_id{};

        /**
         * Scan a Desfire card
         */
        {
            ESP_LOGI("UT", "Attempting to scan for a Desfire card.");
            const auto r_scan = ctrl->initiator_list_passive_kbps106_typea(1, 5000ms);
            if (r_scan) {
                for (auto const &target : *r_scan) {
                    ESP_LOGI("UT", "Logical index %u; NFC ID:", target.logical_index);
                    ESP_LOG_BUFFER_HEX_LEVEL("UT", target.nfcid.data(), target.nfcid.size(), ESP_LOG_INFO);
                    std::copy_n(std::begin(target.nfcid), nfc_id.size(), std::begin(nfc_id));
                    tag = std::make_unique<desfire::tag>(*ctrl, target.logical_index);
                    // We only need one
                    break;
                }
            }

            if (tag == nullptr) {
                ESP_LOGE("UT", "Could not find any tag!");
            }
            REQUIRE(tag != nullptr);
        }

        /**
         * Recover the main key and format
         */
        REQUIRE(card_recover_key_and_format(*tag, nfc_id, true));

        {
            ka::member_token token{*tag};

            const auto r_id = token.get_id();
            CHECK(r_id);

            const auto rkey = bundle.km_kp.derive_token_root_key(*r_id);
            const desfire::any_key default_k{desfire::cipher_type::des};
            const desfire::any_key seondary_k{desfire::cipher_type::aes128, mlab::make_range(sec_keys::aes), 0, sec_keys::version};

            CHECK(ok_and<true>(token.check_root_key(default_k)));
            CHECK(ok_and<false>(token.check_root_key(seondary_k)));

            CHECK(is_err<desfire::error::permission_denied>(token.check_root(rkey)));
            CHECK(token.setup_root(rkey, true));
            CHECK(ok_and<true>(token.check_root_key(rkey)));

            CHECK(ok_and<true>(token.check_root(rkey)));

            CHECK(token.tag().active_app() == desfire::root_app);
            CHECK(token.tag().active_key_no() == 0);

            auto r_rights = token.tag().get_app_settings();
            CHECK(r_rights);

            r_rights->rights.dir_access_without_auth = true;
            r_rights->rights.create_delete_without_master_key = false;

            desfire::esp32::suppress_log suppress{ESP_LOG_ERROR, {"KA"}};

            CHECK(token.tag().change_app_settings(r_rights->rights));
            CHECK(ok_and<false>(token.check_root(rkey)));

            r_rights->rights.dir_access_without_auth = false;
            r_rights->rights.create_delete_without_master_key = true;

            CHECK(token.tag().change_app_settings(r_rights->rights));
            CHECK(ok_and<false>(token.check_root(rkey)));

            r_rights->rights.dir_access_without_auth = true;
            r_rights->rights.create_delete_without_master_key = true;

            CHECK(token.tag().change_app_settings(r_rights->rights));
            CHECK(ok_and<false>(token.check_root(rkey)));

            suppress.restore();

            REQUIRE(token.setup_root(rkey, true));
        }

        {
            ka::member_token token{*tag};

            const auto r_id = token.get_id();
            constexpr desfire::app_id aid = {0xf5, 0x10, 0x01};
            CHECK(r_id);

            const auto rkey = bundle.km_kp.derive_token_root_key(*r_id);
            const auto mkey = bundle.km_kp.derive_gate_app_master_key(*r_id);
            CHECK(ok_and<true>(token.check_root(rkey)));

            /**
             * Test create_gate_app, ensure_gate_app, check_master_key directly with an app.
             */
            {
                CHECK(is_err<desfire::error::parameter_error>(token.create_gate_app({0x00, 0x00, 0x00}, rkey, mkey)));
                REQUIRE(token.create_gate_app(ka::gate_id::first_aid, rkey, mkey));

                CHECK(ok_and<true>(token.check_master_key(mkey, ka::gate_id::first_aid, true)));
                CHECK(is_err<desfire::error::app_not_found>(token.check_master_key(mkey, aid)));

                const ka::gate_app_master_key tweaked_mkey{0, {}};
                CHECK(ok_and<false>(token.check_master_key(tweaked_mkey, ka::gate_id::first_aid, false)));

                CHECK(token.ensure_gate_app(ka::gate_id::first_aid, rkey, mkey));

                CHECK(desfire::fs::login_app(token.tag(), desfire::root_app, rkey));
                CHECK(token.tag().delete_application(ka::gate_id::first_aid));
            }

            /**
             * All master methods should now fail with app_not_found, even if we do not check the app.
             */
            {
                CHECK(is_err<desfire::error::app_not_found>(token.check_master_file(true, false)));
                CHECK(is_err<desfire::error::app_not_found>(token.read_master_file(mkey, true, false)));
                CHECK(is_err<desfire::error::app_not_found>(token.write_master_file(mkey, {}, true)));
                CHECK(is_err<desfire::error::app_not_found>(token.write_encrypted_master_file(bundle.km_kp, {*r_id, {}, {}}, true)));
                CHECK(ok_and<false>(token.is_master_enrolled(true, true)));
                CHECK(is_err<desfire::error::app_not_found>(token.read_encrypted_master_file(bundle.km_kp, true, false)));
                CHECK(is_err<desfire::error::app_not_found>(token.is_deployed_correctly(bundle.km_kp)));

                // They must fail even if we do not test the app
                CHECK(is_err<desfire::error::app_not_found>(token.check_master_file(false, false)));
                CHECK(is_err<desfire::error::app_not_found>(token.read_master_file(mkey, false, false)));
                CHECK(is_err<desfire::error::app_not_found>(token.write_master_file(mkey, {}, false)));
                CHECK(is_err<desfire::error::app_not_found>(token.write_encrypted_master_file(bundle.km_kp, {*r_id, {}, {}}, false)));
                CHECK(ok_and<false>(token.is_master_enrolled(false, false)));
                CHECK(is_err<desfire::error::app_not_found>(token.read_encrypted_master_file(bundle.km_kp, false, false)));
                CHECK(is_err<desfire::error::app_not_found>(token.is_deployed_correctly(bundle.km_kp)));
            }

            /**
             * From now onwards, the first gate app exists
             */
            REQUIRE(token.ensure_gate_app(ka::gate_id::first_aid, rkey, mkey));
            REQUIRE(token.check_gate_app(ka::gate_id::first_aid, true));
            CHECK(is_err<desfire::error::app_not_found>(token.check_gate_app(aid, false)));
            CHECK(is_err<desfire::error::file_not_found>(token.is_deployed_correctly(bundle.km_kp)));

            /**
             * Create a fully working gate
             */
            const auto &g = bundle.g13;
            const auto gid = bundle.g13.id();
            const ka::gate_token_key key = bundle.g13.derive_token_key(*r_id, gid.key_no());

            /**
             * Make sure that all gate methods fail with app not found on the second gate app (which does not
             * exist). These must fail even if we do not test the app.
             * This repeats some of the tests of the master methods, because internally they share the same
             * implementation, but that is ok. Gate methods are more comprehensive, due to listing and enrolling.
             */
            {
                CHECK(is_err<desfire::error::app_not_found>(token.check_gate_file(gid, true, false)));
                CHECK(is_err<desfire::error::app_not_found>(token.read_gate_file(gid, key, true, false)));
                CHECK(is_err<desfire::error::app_not_found>(token.write_gate_file(gid, mkey, {}, true)));
                // Except here, here is true
                CHECK(token.delete_gate_file(gid, mkey, true));
                CHECK(is_err<desfire::error::app_not_found>(token.write_encrypted_gate_file(bundle.km_kp, bundle.g13.public_info(), {*r_id, {}, {}}, true)));
                CHECK(ok_and<false>(token.is_gate_enrolled(gid, true, true)));
                CHECK(is_err<desfire::error::app_not_found>(g.read_encrypted_gate_file(token, true, false)));

                CHECK(is_err<desfire::error::app_not_found>(token.enroll_gate_key(gid, mkey, key, true)));
                CHECK(is_err<desfire::error::app_not_found>(token.unenroll_gate_key(gid, mkey, key, true)));
                CHECK(is_err<desfire::error::app_not_found>(token.check_encrypted_gate_file(bundle.km_kp, bundle.g13_sec_info, {*r_id, {}, {}}, true, true)));

                const auto r_gates = token.list_gates(true, true);
                CHECK(r_gates);
                CHECK(r_gates->empty());

                const auto r_gate_apps = token.list_gate_apps(true);
                CHECK(r_gate_apps);
                CHECK(r_gate_apps->end() == aid);

                // They must fail even if we do not test the app
                CHECK(is_err<desfire::error::app_not_found>(token.check_gate_file(gid, false, false)));
                CHECK(is_err<desfire::error::app_not_found>(token.read_gate_file(gid, key, false, false)));
                CHECK(is_err<desfire::error::app_not_found>(token.write_gate_file(gid, mkey, {}, false)));
                CHECK(token.delete_gate_file(gid, mkey, false));
                CHECK(is_err<desfire::error::app_not_found>(token.write_encrypted_gate_file(bundle.km_kp, bundle.g13.public_info(), {*r_id, {}, {}}, false)));
                CHECK(ok_and<false>(token.is_gate_enrolled(gid, false, false)));
                CHECK(is_err<desfire::error::app_not_found>(g.read_encrypted_gate_file(token, false, false)));

                CHECK(is_err<desfire::error::app_not_found>(token.enroll_gate_key(gid, mkey, key, false)));
                CHECK(is_err<desfire::error::app_not_found>(token.unenroll_gate_key(gid, mkey, key, false)));
                CHECK(is_err<desfire::error::app_not_found>(token.check_encrypted_gate_file(bundle.km_kp, bundle.g13_sec_info, {*r_id, {}, {}}, false, false)));
            }

            /**
             * Create a second app with correct settings but on a wrong key. All methods that require the master key should fail.
             */
            {
                constexpr desfire::key_rights gate_app_rights{0_b, false, true, false, false};
                CHECK(desfire::fs::login_app(token.tag(), desfire::root_app, rkey));
                CHECK(desfire::fs::create_app(token.tag(), aid, key, gate_app_rights, ka::gate_id::gates_per_app));

                // These all should fail with permission denied, independently on whether we check the app or not
                CHECK(is_err<desfire::error::permission_denied>(token.write_gate_file(gid, mkey, {}, true)));
                CHECK(is_err<desfire::error::permission_denied>(token.delete_gate_file(gid, mkey, true)));
                CHECK(is_err<desfire::error::permission_denied>(token.enroll_gate_key(gid, mkey, key, true)));
                CHECK(is_err<desfire::error::permission_denied>(token.unenroll_gate_key(gid, mkey, {gid.key_no(), {}}, true)));
                CHECK(is_err<desfire::error::permission_denied>(token.write_gate_file(gid, mkey, {}, false)));
                CHECK(is_err<desfire::error::permission_denied>(token.delete_gate_file(gid, mkey, false)));
                CHECK(is_err<desfire::error::permission_denied>(token.enroll_gate_key(gid, mkey, key, false)));
                CHECK(is_err<desfire::error::permission_denied>(token.unenroll_gate_key(gid, mkey, {gid.key_no(), {}}, false)));

                CHECK(desfire::fs::login_app(token.tag(), desfire::root_app, rkey));
                CHECK(token.tag().delete_application(aid));
            }

            /**
             * Test each of the app settings individually. Create a valid app with the incorrect key and incorrect
             * settings. Make sure that upon testing, all gate methods fail with app integrity errors, while as
             * when not testing, they fail with the previous error conditions, such as file not existing, or permission
             * denied.
             */
            {
                using create_parms = std::pair<desfire::key_rights, std::uint8_t>;
                constexpr auto correct_extra_keys = std::uint8_t(ka::gate_id::gates_per_app);
                constexpr std::array<create_parms, 6> parms{
                        create_parms{{1_b, false, true, false, false}, correct_extra_keys},
                        create_parms{{0_b, true, true, false, false}, correct_extra_keys},
                        create_parms{{0_b, false, false, false, false}, correct_extra_keys},
                        create_parms{{0_b, false, true, true, false}, correct_extra_keys},
                        create_parms{{0_b, false, true, false, true}, correct_extra_keys},
                        create_parms{{0_b, false, true, false, false}, correct_extra_keys - 1},
                };
                for (auto const &[rights, extra_keys] : parms) {
                    ESP_LOGI("UT", "Testing invalid app settings: "
                                   "change actor=%c, change mkey=%c, dir w/o auth=%c, files w/o mkey=%c, "
                                   "change cfg=%c, extra keys=%d.",
                             rights.allowed_to_change_keys.describe(),
                             boolalpha(rights.master_key_changeable),
                             boolalpha(rights.dir_access_without_auth),
                             boolalpha(rights.create_delete_without_master_key),
                             boolalpha(rights.config_changeable),
                             extra_keys);

                    CHECK(desfire::fs::login_app(token.tag(), desfire::root_app, rkey));
                    CHECK(desfire::fs::create_app(token.tag(), aid, key, rights, extra_keys));
                    REQUIRE(token.ensure_gate_app(ka::gate_id::first_aid, rkey, mkey));
                    {
                        desfire::esp32::suppress_log suppress{ESP_LOG_ERROR, {"KA"}};
                        CHECK(is_err<desfire::error::app_integrity_error>(token.check_gate_file(gid, true, false)));
                        CHECK(is_err<desfire::error::app_integrity_error>(token.read_gate_file(gid, key, true, false)));
                        CHECK(is_err<desfire::error::app_integrity_error>(token.write_gate_file(gid, mkey, {}, true)));
                        CHECK(is_err<desfire::error::app_integrity_error>(token.delete_gate_file(gid, mkey, true)));
                        CHECK(is_err<desfire::error::app_integrity_error>(token.write_encrypted_gate_file(bundle.km_kp, bundle.g13.public_info(), {*r_id, {}, {}}, true)));
                        CHECK(is_err<desfire::error::app_integrity_error>(token.is_gate_enrolled(gid, true, true)));
                        CHECK(is_err<desfire::error::app_integrity_error>(g.read_encrypted_gate_file(token, true, false)));

                        CHECK(is_err<desfire::error::app_integrity_error>(token.enroll_gate_key(gid, mkey, key, true)));
                        CHECK(is_err<desfire::error::app_integrity_error>(token.unenroll_gate_key(gid, mkey, {gid.key_no(), {}}, true)));
                        CHECK(is_err<desfire::error::app_integrity_error>(token.check_encrypted_gate_file(bundle.km_kp, bundle.g13_sec_info, {*r_id, {}, {}}, true, true)));

                        const auto r_gates = token.list_gates(true, true);
                        CHECK(r_gates);
                        CHECK(r_gates->empty());

                        auto r_gate_apps = token.list_gate_apps(true);
                        CHECK(r_gate_apps);
                        CHECK(r_gate_apps->end() == aid);
                        suppress.restore();

                        // Check gate file will try query the file settings, so it will know if the app settings are incorrect!
                        if (rights.dir_access_without_auth) {
                            CHECK(is_err<desfire::error::file_not_found>(token.check_gate_file(gid, false, false)));
                            CHECK(ok_and<false>(token.is_gate_enrolled(gid, false, false)));
                        } else {
                            suppress.suppress();
                            CHECK(is_err<desfire::error::app_integrity_error>(token.check_gate_file(gid, false, false)));
                            CHECK(is_err<desfire::error::app_integrity_error>(token.is_gate_enrolled(gid, false, false)));
                            // Moreover, also these will cascade-fail when we enable file checking!
                            CHECK(is_err<desfire::error::app_integrity_error>(token.is_gate_enrolled(gid, false, true)));
                            CHECK(is_err<desfire::error::app_integrity_error>(token.read_gate_file(gid, key, false, true)));
                            CHECK(is_err<desfire::error::app_integrity_error>(token.is_gate_enrolled(gid, false, true)));
                            CHECK(is_err<desfire::error::app_integrity_error>(g.read_encrypted_gate_file(token, false, true)));
                            CHECK(is_err<desfire::error::app_integrity_error>(token.check_encrypted_gate_file(bundle.km_kp, bundle.g13_sec_info, {*r_id, {}, {}}, false, true)));
                            suppress.restore();
                        }
                        // These pass if we do not check the app
                        CHECK(is_err<desfire::error::permission_denied>(token.read_gate_file(gid, key, false, false)));
                        CHECK(is_err<desfire::error::permission_denied>(token.write_gate_file(gid, mkey, {}, false)));
                        CHECK(is_err<desfire::error::permission_denied>(token.delete_gate_file(gid, mkey, false)));
                        CHECK(is_err<desfire::error::permission_denied>(token.write_encrypted_gate_file(bundle.km_kp, bundle.g13.public_info(), {*r_id, {}, {}}, false)));
                        CHECK(is_err<desfire::error::permission_denied>(g.read_encrypted_gate_file(token, false, false)));
                        CHECK(is_err<desfire::error::permission_denied>(token.enroll_gate_key(gid, mkey, key, false)));
                        CHECK(is_err<desfire::error::permission_denied>(token.unenroll_gate_key(gid, mkey, {gid.key_no(), {}}, false)));
                        CHECK(is_err<desfire::error::permission_denied>(token.check_encrypted_gate_file(bundle.km_kp, bundle.g13_sec_info, {*r_id, {}, {}}, false, false)));

                        r_gate_apps = token.list_gate_apps(false);
                        CHECK(r_gate_apps);
                        CHECK(r_gate_apps->end() == ka::unpack_app_id(ka::pack_app_id(aid) + 1));
                    }
                    CHECK(desfire::fs::login_app(token.tag(), desfire::root_app, rkey));
                    REQUIRE(token.tag().format_picc());
                }
            }
        }

        {
            ka::member_token token{*tag};

            const auto r_id = token.get_id();
            CHECK(r_id);

            const ka::identity real_identity{*r_id, "Holder", "Publisher"};

            const auto rkey = bundle.km_kp.derive_token_root_key(*r_id);
            const auto mkey = bundle.km_kp.derive_gate_app_master_key(*r_id);
            CHECK(ok_and<true>(token.check_root(rkey)));


            /**
             * Create a fully working gate
             */
            const auto &g = bundle.g0;
            const auto gid = bundle.g0.id();
            const ka::gate_token_key key = bundle.g0.derive_token_key(*r_id, gid.key_no());

            REQUIRE(token.ensure_gate_app(ka::gate_id::first_aid, rkey, mkey));
            REQUIRE(token.unenroll_gate_key(gid, mkey, key, true));
            REQUIRE(token.enroll_gate_key(gid, mkey, key, true));
            REQUIRE(token.unenroll_gate_key(gid, mkey, key, true));
            REQUIRE(token.enroll_gate_key(gid, mkey, key, true));
            CHECK(is_err<desfire::error::app_integrity_error>(token.unenroll_gate_key(gid, mkey, {gid.key_no(), {}}, true)));

            /**
             * Test that reading fails with file_not_found independently of checking
             */
            {
                CHECK(is_err<desfire::error::file_not_found>(token.read_master_file(mkey, false, true)));
                CHECK(is_err<desfire::error::file_not_found>(token.read_master_file(mkey, false, false)));
                CHECK(is_err<desfire::error::file_not_found>(token.read_gate_file(gid, key, false, true)));
                CHECK(is_err<desfire::error::file_not_found>(token.read_gate_file(gid, key, false, false)));
                CHECK(is_err<desfire::error::file_not_found>(token.read_encrypted_master_file(bundle.km_kp, false, true)));
                CHECK(is_err<desfire::error::file_not_found>(token.read_encrypted_master_file(bundle.km_kp, false, false)));
                CHECK(is_err<desfire::error::file_not_found>(g.read_encrypted_gate_file(token, false, true)));
                CHECK(is_err<desfire::error::file_not_found>(g.read_encrypted_gate_file(token, false, false)));

                CHECK(is_err<desfire::error::file_not_found>(token.check_gate_file(gid, false, false)));
                CHECK(is_err<desfire::error::file_not_found>(token.check_master_file(false, false)));

                CHECK(ok_and<false>(token.is_gate_enrolled(gid, false, true)));
                CHECK(ok_and<false>(token.is_master_enrolled(false, true)));
                CHECK(is_err<desfire::error::file_not_found>(token.is_gate_enrolled_correctly(bundle.km_kp, bundle.g0_sec_info)));
                CHECK(ok_and<false>(token.is_master_enrolled(false, true)));
                CHECK(is_err<desfire::error::file_not_found>(token.is_deployed_correctly(bundle.km_kp)));
            }

            /**
             * Test different files with invalid settings.
             */
            {
                using desfire::file_access_rights;
                using desfire::file_security;
                using desfire::file_type;
                using desfire::no_key;
                using std_settings = desfire::file_settings<file_type::standard>;
                using val_settings = desfire::file_settings<file_type::value>;

                const std::array<desfire::any_file_settings, 6> invalid_master_settings = {
                        std_settings{file_security::authenticated, file_access_rights{no_key, no_key, 0_b, no_key}, 1},
                        std_settings{file_security::encrypted, file_access_rights{0_b, no_key, 0_b, no_key}, 1},
                        std_settings{file_security::encrypted, file_access_rights{no_key, 0_b, 0_b, no_key}, 1},
                        std_settings{file_security::encrypted, file_access_rights{no_key, no_key, no_key, no_key}, 1},
                        std_settings{file_security::encrypted, file_access_rights{no_key, no_key, 0_b, 0_b}, 1},
                        val_settings{file_security::encrypted, file_access_rights{no_key, no_key, 0_b, no_key}, 0, 0, 0, false}};

                const std::array<desfire::any_file_settings, 6> invalid_gate_settings = {
                        std_settings{file_security::authenticated, file_access_rights{no_key, no_key, gid.key_no(), no_key}, 1},
                        std_settings{file_security::encrypted, file_access_rights{0_b, no_key, gid.key_no(), no_key}, 1},
                        std_settings{file_security::encrypted, file_access_rights{no_key, 0_b, gid.key_no(), no_key}, 1},
                        std_settings{file_security::encrypted, file_access_rights{no_key, no_key, no_key, no_key}, 1},
                        std_settings{file_security::encrypted, file_access_rights{no_key, no_key, gid.key_no(), 0_b}, 1},
                        val_settings{file_security::encrypted, file_access_rights{no_key, no_key, gid.key_no(), no_key}, 0, 0, 0, false}};

                const auto [aid, fid] = gid.app_and_file();

                for (auto const &settings : invalid_master_settings) {
                    if (settings.type() == file_type::standard) {
                        ESP_LOGI("UT", "Testing invalid master std file settings: "
                                       "sec=%s, rw=%c, chg=%c, r=%c, w=%c",
                                 desfire::to_string(settings.common_settings().security),
                                 settings.common_settings().rights.read_write.describe(),
                                 settings.common_settings().rights.change.describe(),
                                 settings.common_settings().rights.read.describe(),
                                 settings.common_settings().rights.write.describe());
                    } else {
                        ESP_LOGI("UT", "Testing invalid master file type.");
                    }

                    CHECK(desfire::fs::login_app(token.tag(), aid, mkey));
                    CHECK(token.tag().create_file(0x00, settings));

                    desfire::esp32::suppress_log suppress{"KA"};
                    CHECK(is_err<desfire::error::file_integrity_error>(token.read_master_file(mkey, false, true)));
                    CHECK(is_err<desfire::error::file_integrity_error>(token.read_encrypted_master_file(bundle.km_kp, false, true)));

                    if (settings.common_settings().security != file_security::encrypted or
                        settings.common_settings().rights.read != 0_b or
                        settings.type() != file_type::standard) {
                        CHECK(is_err<desfire::error::file_integrity_error>(token.read_master_file(mkey, false, false)));
                        CHECK(is_err<desfire::error::file_integrity_error>(token.read_encrypted_master_file(bundle.km_kp, false, false)));
                    } else {
                        // This one passes
                        CHECK(token.read_master_file(mkey, false, false));
                        CHECK(is_err<desfire::error::crypto_error>(token.read_encrypted_master_file(bundle.km_kp, false, false)));
                    }

                    CHECK(ok_and<false>(token.check_master_file(false, false)));
                    CHECK(is_err<desfire::error::file_integrity_error>(token.is_master_enrolled(false, true)));
                    // This one passes
                    CHECK(ok_and<true>(token.is_master_enrolled(false, false)));
                    CHECK(is_err<desfire::error::file_integrity_error>(token.is_deployed_correctly(bundle.km_kp)));

                    CHECK(desfire::fs::login_app(token.tag(), aid, mkey));
                    CHECK(token.tag().delete_file(0x00));
                }

                /**
                 * We need an actual master file to test at a gate file level
                 */
                CHECK(is_err<desfire::error::parameter_error>(token.write_encrypted_master_file(bundle.km_kp, ka::identity{}, true)));
                REQUIRE(token.write_encrypted_master_file(bundle.km_kp, real_identity, true));
                const auto r_identity = token.read_encrypted_master_file(bundle.km_kp, true, true);
                CHECK(r_identity);
                CHECK(*r_identity == real_identity);
                CHECK(ok_and<true>(token.is_master_enrolled(true, true)));
                REQUIRE(token.is_deployed_correctly(bundle.km_kp));

                for (auto const &settings : invalid_gate_settings) {
                    if (settings.type() == file_type::standard) {
                        ESP_LOGI("UT", "Testing invalid std file settings: "
                                       "sec=%s, rw=%c, chg=%c, r=%c, w=%c",
                                 desfire::to_string(settings.common_settings().security),
                                 settings.common_settings().rights.read_write.describe(),
                                 settings.common_settings().rights.change.describe(),
                                 settings.common_settings().rights.read.describe(),
                                 settings.common_settings().rights.write.describe());
                    } else {
                        ESP_LOGI("UT", "Testing invalid file type.");
                    }

                    CHECK(desfire::fs::login_app(token.tag(), aid, mkey));
                    CHECK(token.tag().create_file(fid, settings));

                    desfire::esp32::suppress_log suppress{"KA"};
                    CHECK(is_err<desfire::error::file_integrity_error>(token.read_gate_file(gid, key, false, true)));
                    CHECK(is_err<desfire::error::file_integrity_error>(g.read_encrypted_gate_file(token, false, true)));

                    if (settings.common_settings().security != file_security::encrypted or
                        settings.common_settings().rights.read != gid.key_no() or
                        settings.type() != file_type::standard) {
                        CHECK(is_err<desfire::error::file_integrity_error>(token.read_gate_file(gid, key, false, false)));
                        CHECK(is_err<desfire::error::file_integrity_error>(g.read_encrypted_gate_file(token, false, false)));
                    } else {
                        // This one passes
                        CHECK(token.read_gate_file(gid, key, false, false));
                        CHECK(is_err<desfire::error::crypto_error>(g.read_encrypted_gate_file(token, false, false)));
                    }

                    CHECK(ok_and<false>(token.check_gate_file(gid, false, false)));
                    CHECK(is_err<desfire::error::file_integrity_error>(token.is_gate_enrolled(gid, false, true)));
                    // This one passes
                    CHECK(ok_and<true>(token.is_gate_enrolled(gid, false, false)));
                    CHECK(is_err<desfire::error::file_integrity_error>(token.is_gate_enrolled_correctly(bundle.km_kp, bundle.g0_sec_info)));

                    // Also this one
                    auto r_list = token.list_gates(false, false);
                    CHECK(r_list);
                    CHECK(r_list->size() == 1);
                    CHECK(r_list->front() == gid);

                    r_list = token.list_gates(false, true);
                    CHECK(r_list);
                    CHECK(r_list->empty());


                    CHECK(desfire::fs::login_app(token.tag(), aid, mkey));
                    CHECK(token.tag().delete_file(fid));
                }
            }

            /**
             * Now make sure that real gate enrollment works.
             */
            {
                // Note: a key is already enrolled, so this tests that re-enrolling works correctly
                const ka::identity fake_identity{*r_id, "Not me", {}};

                CHECK(token.delete_gate_file(bundle.g0.id(), mkey, true));
                REQUIRE(token.write_encrypted_gate_file(bundle.km_kp, bundle.g0.public_info(), fake_identity, true));
                CHECK(ok_and<true>(token.is_gate_enrolled(gid, true, true)));
                CHECK(ok_and<true>(token.check_gate_file(gid, true, true)));
                CHECK(token.read_gate_file(gid, key, true, true));
                CHECK(g.read_encrypted_gate_file(token, true, true));

                // Fake identity: must fail the "correctly" check
                CHECK(ok_and<false>(token.is_gate_enrolled_correctly(bundle.km_kp, bundle.g0_sec_info)));

                auto r_list = token.list_gates(true, true);
                CHECK(r_list);
                CHECK(r_list->size() == 1);
                CHECK(r_list->front() == gid);

                // Attempting to enroll a fake identity should trigger parm error at this stage!
                CHECK(is_err<desfire::error::parameter_error>(token.enroll_gate(bundle.km_kp, bundle.g0_sec_info, fake_identity)));

                // Right, let's do this with the correct identity
                REQUIRE(token.write_encrypted_gate_file(bundle.km_kp, bundle.g0.public_info(), real_identity, true));
                CHECK(ok_and<true>(token.is_gate_enrolled_correctly(bundle.km_kp, bundle.g0_sec_info)));

                // Let's assert that the top-level enrollment works too
                CHECK(is_err<desfire::error::parameter_error>(token.enroll_gate(bundle.km_kp, bundle.g0_sec_info, fake_identity)));
                REQUIRE(token.enroll_gate(bundle.km_kp, bundle.g0_sec_info, real_identity));

                // And finally let us assert that listing the gates includes the one we just got
                r_list = token.list_gates(true, true);
                CHECK(r_list);
                CHECK(r_list->size() == 1);
                CHECK(r_list->front() == gid);

                // Now let's delete it
                REQUIRE(token.delete_gate_file(bundle.g0.id(), mkey, true));
                // And check it's not there anymore
                CHECK(ok_and<false>(token.is_gate_enrolled(gid, true, true)));
                // Get rid of the key too
                REQUIRE(token.unenroll_gate_key(bundle.g0.id(), mkey, key, true));
            }
        }

        {
            ka::member_token token{*tag};

            const auto r_id = token.get_id();
            CHECK(r_id);

            const ka::identity real_identity{*r_id, "Holder", "Publisher"};

            const auto rkey = bundle.km_kp.derive_token_root_key(*r_id);
            CHECK(ok_and<true>(token.check_root(rkey)));

            CHECK(token.tag().format_picc());

            CHECK(is_err<desfire::error::app_not_found>(token.is_deployed_correctly(bundle.km_kp)));
            CHECK(ok_and<false>(token.is_master_enrolled(true, true)));

            CHECK(token.deploy(bundle.km_kp, real_identity));
            CHECK(ok_and<true>(token.is_master_enrolled(true, true)));
            CHECK(token.is_deployed_correctly(bundle.km_kp));

            CHECK(ok_and<false>(token.is_gate_enrolled(bundle.g0.id(), true, true)));
            CHECK(is_err<desfire::error::file_not_found>(token.is_gate_enrolled_correctly(bundle.km_kp, bundle.g0_sec_info)));
            CHECK(token.enroll_gate(bundle.km_kp, bundle.g0_sec_info, real_identity));
            CHECK(ok_and<true>(token.is_master_enrolled(true, true)));

            CHECK(token.is_deployed_correctly(bundle.km_kp));
            CHECK(ok_and<true>(token.is_gate_enrolled(bundle.g0.id(), true, true)));
            CHECK(token.is_gate_enrolled_correctly(bundle.km_kp, bundle.g0_sec_info));

            // Does it work twice in a row?
            CHECK(token.enroll_gate(bundle.km_kp, bundle.g0_sec_info, real_identity));
            CHECK(ok_and<true>(token.is_master_enrolled(true, true)));

            CHECK(token.is_deployed_correctly(bundle.km_kp));
            CHECK(ok_and<true>(token.is_gate_enrolled(bundle.g0.id(), true, true)));
            CHECK(token.is_gate_enrolled_correctly(bundle.km_kp, bundle.g0_sec_info));

            // Does it access?
            const auto r_gate_id = bundle.g0.read_encrypted_gate_file(token, true, true);
            CHECK(r_gate_id);
            const auto r_master_id = token.read_encrypted_master_file(bundle.km_kp, true, true);
            CHECK(r_master_id);
            CHECK(*r_gate_id == *r_master_id);

            // Benchmark reading the gate file
            ESP_LOGI("UT", "Benchmarking read_encrypted_gate_file...");
            static constexpr auto n_tests = 20;
            mlab::timer t;
            for (std::size_t i = 0; i < n_tests; ++i) {
                CHECK(bundle.g0.read_encrypted_gate_file(token, true, true));
            }
            const auto elapsed = t.elapsed();
            ESP_LOGI("UT", "Benchmark ended, average time: %0.f ms.", double(elapsed.count()) / n_tests);

            // Does it work with a different gate app?
            CHECK(ok_and<false>(token.is_gate_enrolled(bundle.g13.id(), true, true)));
            CHECK(is_err<desfire::error::app_not_found>(token.is_gate_enrolled_correctly(bundle.km_kp, bundle.g13_sec_info)));
            CHECK(token.enroll_gate(bundle.km_kp, bundle.g13_sec_info, real_identity));
            CHECK(ok_and<true>(token.is_master_enrolled(true, true)));

            CHECK(token.is_deployed_correctly(bundle.km_kp));
            CHECK(ok_and<true>(token.is_gate_enrolled(bundle.g13.id(), true, true)));
            CHECK(token.is_gate_enrolled_correctly(bundle.km_kp, bundle.g13_sec_info));

            // Does it work twice in a row?
            CHECK(token.enroll_gate(bundle.km_kp, bundle.g13_sec_info, real_identity));
            CHECK(ok_and<true>(token.is_master_enrolled(true, true)));

            CHECK(token.is_deployed_correctly(bundle.km_kp));
            CHECK(ok_and<true>(token.is_gate_enrolled(bundle.g13.id(), true, true)));
            CHECK(token.is_gate_enrolled_correctly(bundle.km_kp, bundle.g13_sec_info));

            // Does deleting it work?
            CHECK(token.unenroll_gate(bundle.km_kp, bundle.g13_sec_info));
            CHECK(ok_and<false>(token.is_gate_enrolled(bundle.g13.id(), true, true)));
            // Does it work twice?
            CHECK(token.unenroll_gate(bundle.km_kp, bundle.g13_sec_info));
        }

        /**
         * Cleanup after using.
         */
        CHECK(card_recover_key_and_format(*tag, nfc_id, false));
    }

}// namespace ut