#include <chrono>
#include <desfire/esp32/utils.hpp>
#include <ka/config.hpp>
#include <ka/desfire_fs.hpp>
#include <ka/gate.hpp>
#include <ka/key_pair.hpp>
#include <ka/keymaker.hpp>
#include <ka/member_token.hpp>
#include <ka/nvs.hpp>
#include <mlab/strutils.hpp>
#include <pn532/esp32/hsu.hpp>
#include <thread>
#include <unity.h>

using namespace ka;
using namespace std::chrono_literals;

namespace ut {

    void test_encrypt_decrypt() {
        const mlab::bin_data message = mlab::data_from_string("The quick brown fox jumps over the lazy dog");
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

        TEST_ASSERT(k1.encrypt_for(k2, buffer));
        mlab::bin_data test_buffer = message;

        TEST_ASSERT(k1.blind_check_ciphertext(k2, test_buffer, buffer));
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

        using namespace ::mlab_literals;

        constexpr char boolalpha(bool b) {
            return b ? 'Y' : 'N';
        }

        struct test_bundle {
            ka::key_pair kp{{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
                             0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f}};
            ka::keymaker km{kp};
            ka::gate g0{ka::key_pair{{0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
                                      0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f}},
                        0_g,
                        ka::pub_key{kp.raw_pk()},
                        {0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f,
                         0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4a, 0x4b, 0x4c, 0x4d, 0x4e, 0x4f}};
            ka::gate g13{ka::key_pair{{0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58, 0x59, 0x5a, 0x5b, 0x5c, 0x5d, 0x5e, 0x5f,
                                       0x60, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69, 0x6a, 0x6b, 0x6c, 0x6d, 0x6e, 0x6f}},
                         13_g,
                         ka::pub_key{kp.raw_pk()},
                         {0x70, 0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77, 0x78, 0x79, 0x7a, 0x7b, 0x7c, 0x7d, 0x7e, 0x7f,
                          0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88, 0x89, 0x8a, 0x8b, 0x8c, 0x8d, 0x8e, 0x8f}};
            ka::gate_config g0_cfg{gate_credentials{ka::pub_key{g0.keys().raw_pk()}, g0.app_base_key()}, 0_g};
            ka::gate_config g13_cfg{gate_credentials{ka::pub_key{g13.keys().raw_pk()}, g13.app_base_key()}, 13_g};
            ka::identity id{{}, "Test user", "Test deployer"};
        } const bundle{};

        using namespace ::desfire::esp32;
    }// namespace

    template <class Result>
    [[nodiscard]] bool passthru_set(bool &dest, Result const &res);

    template <class Result>
    [[nodiscard]] bool passthru_and(bool &dest, Result const &res);

    template <bool B, class Result>
    [[nodiscard]] bool ok_and(Result const &res);

    template <desfire::error E, class Result>
    [[nodiscard]] bool is_err(Result const &res);

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
        const ka::key_pair demo_key_pair{ka::pwhash, "foobar"};

        const std::array<desfire::any_key, 11> keys_to_test{
                default_k,
                bundle.kp.derive_token_root_key(instance.nfc_id),
                r_info ? bundle.kp.derive_token_root_key(token_id{r_info->serial_no}) : default_k,
                r_info ? demo_key_pair.derive_token_root_key(token_id{r_info->serial_no}) : default_k,
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
            auto suppress = suppress_log{DESFIRE_LOG_PREFIX};
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

    void test_root_ops() {
        TEST_ASSERT(instance.tag != nullptr);
        if (instance.tag == nullptr) {
            return;
        }

        member_token token{*instance.tag};

        const auto r_id = token.get_id();
        TEST_ASSERT(r_id);

        const auto rkey = bundle.kp.derive_token_root_key(*r_id);
        const desfire::any_key default_k{desfire::cipher_type::des};
        const desfire::any_key seondary_k{desfire::cipher_type::aes128, mlab::make_range(secondary_aes_key), 0, secondary_keys_version};

        TEST_ASSERT(ok_and<true>(token.check_root_key(default_k)));
        TEST_ASSERT(ok_and<false>(token.check_root_key(seondary_k)));

        TEST_ASSERT(is_err<desfire::error::permission_denied>(token.check_root(rkey)));
        TEST_ASSERT(token.setup_root(rkey, true));
        TEST_ASSERT(ok_and<true>(token.check_root_key(rkey)));

        TEST_ASSERT(ok_and<true>(token.check_root(rkey)));

        TEST_ASSERT(token.tag().active_app() == desfire::root_app);
        TEST_ASSERT(token.tag().active_key_no() == 0);

        auto r_rights = token.tag().get_app_settings();
        TEST_ASSERT(r_rights);

        r_rights->rights.dir_access_without_auth = true;
        r_rights->rights.create_delete_without_master_key = false;

        desfire::esp32::suppress_log suppress{ESP_LOG_ERROR, {"KA"}};

        TEST_ASSERT(token.tag().change_app_settings(r_rights->rights));
        TEST_ASSERT(ok_and<false>(token.check_root(rkey)));

        r_rights->rights.dir_access_without_auth = false;
        r_rights->rights.create_delete_without_master_key = true;

        TEST_ASSERT(token.tag().change_app_settings(r_rights->rights));
        TEST_ASSERT(ok_and<false>(token.check_root(rkey)));

        r_rights->rights.dir_access_without_auth = true;
        r_rights->rights.create_delete_without_master_key = true;

        TEST_ASSERT(token.tag().change_app_settings(r_rights->rights));
        TEST_ASSERT(ok_and<false>(token.check_root(rkey)));

        suppress.restore();

        TEST_ASSERT(token.setup_root(rkey, true));
    };

    void test_app_ops() {
        TEST_ASSERT(instance.tag != nullptr);
        if (instance.tag == nullptr) {
            return;
        }

        member_token token{*instance.tag};

        const auto r_id = token.get_id();
        constexpr desfire::app_id aid = {0xf5, 0x10, 0x01};
        TEST_ASSERT(r_id);

        const auto rkey = bundle.kp.derive_token_root_key(*r_id);
        const auto mkey = bundle.kp.derive_gate_app_master_key(*r_id);
        TEST_ASSERT(ok_and<true>(token.check_root(rkey)));

        /**
         * Test create_gate_app, ensure_gate_app, check_master_key directly with an app.
         */
        {
            TEST_ASSERT(is_err<desfire::error::parameter_error>(token.create_gate_app({0x00, 0x00, 0x00}, rkey, mkey)));
            TEST_ASSERT(token.create_gate_app(gate_id::first_aid, rkey, mkey));

            TEST_ASSERT(ok_and<true>(token.check_master_key(mkey, gate_id::first_aid, true)));
            TEST_ASSERT(is_err<desfire::error::app_not_found>(token.check_master_key(mkey, aid)));

            const gate_app_master_key tweaked_mkey{0, {}};
            TEST_ASSERT(ok_and<false>(token.check_master_key(tweaked_mkey, gate_id::first_aid, false)));

            TEST_ASSERT(token.ensure_gate_app(gate_id::first_aid, rkey, mkey));

            TEST_ASSERT(desfire::fs::login_app(token.tag(), desfire::root_app, rkey));
            TEST_ASSERT(token.tag().delete_application(gate_id::first_aid));
        }

        /**
         * All master methods should now fail with app_not_found, even if we do not check the app.
         */
        {
            TEST_ASSERT(is_err<desfire::error::app_not_found>(token.check_master_file(true, false)));
            TEST_ASSERT(is_err<desfire::error::app_not_found>(token.read_master_file(mkey, true, false)));
            TEST_ASSERT(is_err<desfire::error::app_not_found>(token.write_master_file(mkey, {}, true)));
            TEST_ASSERT(is_err<desfire::error::app_not_found>(token.write_encrypted_master_file(bundle.km, {}, true)));
            TEST_ASSERT(ok_and<false>(token.is_master_enrolled(true, true)));
            TEST_ASSERT(is_err<desfire::error::app_not_found>(token.read_encrypted_master_file(bundle.km, true, false)));
            TEST_ASSERT(is_err<desfire::error::app_not_found>(token.is_deployed_correctly(bundle.km)));

            // They must fail even if we do not test the app
            TEST_ASSERT(is_err<desfire::error::app_not_found>(token.check_master_file(false, false)));
            TEST_ASSERT(is_err<desfire::error::app_not_found>(token.read_master_file(mkey, false, false)));
            TEST_ASSERT(is_err<desfire::error::app_not_found>(token.write_master_file(mkey, {}, false)));
            TEST_ASSERT(is_err<desfire::error::app_not_found>(token.write_encrypted_master_file(bundle.km, {}, false)));
            TEST_ASSERT(ok_and<false>(token.is_master_enrolled(false, false)));
            TEST_ASSERT(is_err<desfire::error::app_not_found>(token.read_encrypted_master_file(bundle.km, false, false)));
            TEST_ASSERT(is_err<desfire::error::app_not_found>(token.is_deployed_correctly(bundle.km)));
        }

        /**
         * From now onwards, the first gate app exists
         */
        TEST_ASSERT(token.ensure_gate_app(gate_id::first_aid, rkey, mkey));
        TEST_ASSERT(token.check_gate_app(gate_id::first_aid, true));
        TEST_ASSERT(is_err<desfire::error::app_not_found>(token.check_gate_app(aid, false)));
        TEST_ASSERT(is_err<desfire::error::file_not_found>(token.is_deployed_correctly(bundle.km)));

        /**
         * Create a fully working gate
         */
        const auto &g = bundle.g13;
        const auto gid = bundle.g13.id();
        const auto &cfg = bundle.g13_cfg;
        const gate_token_key key = bundle.g13.app_base_key().derive_token_key(*r_id, gid.key_no());

        /**
         * Make sure that all gate methods fail with app not found on the second gate app (which does not
         * exist). These must fail even if we do not test the app.
         * This repeats some of the tests of the master methods, because internally they share the same
         * implementation, but that is ok. Gate methods are more comprehensive, due to listing and enrolling.
         */
        {
            TEST_ASSERT(is_err<desfire::error::app_not_found>(token.check_gate_file(gid, true, false)));
            TEST_ASSERT(is_err<desfire::error::app_not_found>(token.read_gate_file(gid, key, true, false)));
            TEST_ASSERT(is_err<desfire::error::app_not_found>(token.write_gate_file(gid, mkey, {}, true)));
            TEST_ASSERT(is_err<desfire::error::app_not_found>(token.write_encrypted_gate_file(bundle.km, cfg, {}, true)));
            TEST_ASSERT(ok_and<false>(token.is_gate_enrolled(gid, true, true)));
            TEST_ASSERT(is_err<desfire::error::app_not_found>(token.read_encrypted_gate_file(g, true, false)));

            TEST_ASSERT(is_err<desfire::error::app_not_found>(token.enroll_gate_key(gid, mkey, key, true)));
            TEST_ASSERT(is_err<desfire::error::app_not_found>(token.check_encrypted_gate_file(bundle.km, cfg, {}, true, true)));

            const auto r_gates = token.list_gates(true, true);
            TEST_ASSERT(r_gates);
            TEST_ASSERT(r_gates->empty());

            const auto r_gate_apps = token.list_gate_apps(true);
            TEST_ASSERT(r_gate_apps);
            TEST_ASSERT(r_gate_apps->end() == aid);

            // They must fail even if we do not test the app
            TEST_ASSERT(is_err<desfire::error::app_not_found>(token.check_gate_file(gid, false, false)));
            TEST_ASSERT(is_err<desfire::error::app_not_found>(token.read_gate_file(gid, key, false, false)));
            TEST_ASSERT(is_err<desfire::error::app_not_found>(token.write_gate_file(gid, mkey, {}, false)));
            TEST_ASSERT(is_err<desfire::error::app_not_found>(token.write_encrypted_gate_file(bundle.km, cfg, {}, false)));
            TEST_ASSERT(ok_and<false>(token.is_gate_enrolled(gid, false, false)));
            TEST_ASSERT(is_err<desfire::error::app_not_found>(token.read_encrypted_gate_file(g, false, false)));

            TEST_ASSERT(is_err<desfire::error::app_not_found>(token.enroll_gate_key(gid, mkey, key, false)));
            TEST_ASSERT(is_err<desfire::error::app_not_found>(token.check_encrypted_gate_file(bundle.km, cfg, {}, false, false)));
        }

        /**
         * Create a second app with correct settings but on a wrong key. All methods that require the master key should fail.
         */
        {
            constexpr desfire::key_rights gate_app_rights{0_b, false, true, false, false};
            TEST_ASSERT(desfire::fs::login_app(token.tag(), desfire::root_app, rkey));
            TEST_ASSERT(desfire::fs::create_app(token.tag(), aid, key, gate_app_rights, ka::gate_id::gates_per_app));

            // These all should fail with permission denied, independently on whether we check the app or not
            TEST_ASSERT(is_err<desfire::error::permission_denied>(token.write_gate_file(gid, mkey, {}, true)));
            TEST_ASSERT(is_err<desfire::error::permission_denied>(token.enroll_gate_key(gid, mkey, key, true)));
            TEST_ASSERT(is_err<desfire::error::permission_denied>(token.write_gate_file(gid, mkey, {}, false)));
            TEST_ASSERT(is_err<desfire::error::permission_denied>(token.enroll_gate_key(gid, mkey, key, false)));

            TEST_ASSERT(desfire::fs::login_app(token.tag(), desfire::root_app, rkey));
            TEST_ASSERT(token.tag().delete_application(aid));
        }

        /**
         * Test each of the app settings individually. Create a valid app with the incorrect key and incorrect
         * settings. Make sure that upon testing, all gate methods fail with app integrity errors, while as
         * when not testing, they fail with the previous error conditions, such as file not existing, or permission
         * denied.
         */
        {
            using create_parms = std::pair<desfire::key_rights, std::uint8_t>;
            constexpr auto correct_extra_keys = std::uint8_t(gate_id::gates_per_app);
            constexpr std::array<create_parms, 6> parms{
                    create_parms{{1_b, false, true, false, false}, correct_extra_keys},
                    create_parms{{0_b, true, true, false, false}, correct_extra_keys},
                    create_parms{{0_b, false, false, false, false}, correct_extra_keys},
                    create_parms{{0_b, false, true, true, false}, correct_extra_keys},
                    create_parms{{0_b, false, true, false, true}, correct_extra_keys},
                    create_parms{{0_b, false, true, false, false}, correct_extra_keys - 1},
            };
            for (auto const &[rights, extra_keys] : parms) {
                ESP_LOGI("TEST", "Testing invalid app settings: "
                                 "change actor=%c, change mkey=%c, dir w/o auth=%c, files w/o mkey=%c, "
                                 "change cfg=%c, extra keys=%d.",
                         rights.allowed_to_change_keys.describe(),
                         boolalpha(rights.master_key_changeable),
                         boolalpha(rights.dir_access_without_auth),
                         boolalpha(rights.create_delete_without_master_key),
                         boolalpha(rights.config_changeable),
                         extra_keys);

                TEST_ASSERT(desfire::fs::login_app(token.tag(), desfire::root_app, rkey));
                TEST_ASSERT(desfire::fs::create_app(token.tag(), aid, key, rights, extra_keys));
                TEST_ASSERT(token.ensure_gate_app(gate_id::first_aid, rkey, mkey));
                {
                    desfire::esp32::suppress_log suppress{ESP_LOG_ERROR, {"KA"}};
                    TEST_ASSERT(is_err<desfire::error::app_integrity_error>(token.check_gate_file(gid, true, false)));
                    TEST_ASSERT(is_err<desfire::error::app_integrity_error>(token.read_gate_file(gid, key, true, false)));
                    TEST_ASSERT(is_err<desfire::error::app_integrity_error>(token.write_gate_file(gid, mkey, {}, true)));
                    TEST_ASSERT(is_err<desfire::error::app_integrity_error>(token.write_encrypted_gate_file(bundle.km, cfg, {}, true)));
                    TEST_ASSERT(is_err<desfire::error::app_integrity_error>(token.is_gate_enrolled(gid, true, true)));
                    TEST_ASSERT(is_err<desfire::error::app_integrity_error>(token.read_encrypted_gate_file(g, true, false)));

                    TEST_ASSERT(is_err<desfire::error::app_integrity_error>(token.enroll_gate_key(gid, mkey, key, true)));
                    TEST_ASSERT(is_err<desfire::error::app_integrity_error>(token.check_encrypted_gate_file(bundle.km, cfg, {}, true, true)));

                    const auto r_gates = token.list_gates(true, true);
                    TEST_ASSERT(r_gates);
                    TEST_ASSERT(r_gates->empty());

                    auto r_gate_apps = token.list_gate_apps(true);
                    TEST_ASSERT(r_gate_apps);
                    TEST_ASSERT(r_gate_apps->end() == aid);
                    suppress.restore();

                    // Check gate file will try query the file settings, so it will know if the app settings are incorrect!
                    if (rights.dir_access_without_auth) {
                        TEST_ASSERT(is_err<desfire::error::file_not_found>(token.check_gate_file(gid, false, false)));
                        TEST_ASSERT(ok_and<false>(token.is_gate_enrolled(gid, false, false)));
                    } else {
                        suppress.suppress();
                        TEST_ASSERT(is_err<desfire::error::app_integrity_error>(token.check_gate_file(gid, false, false)));
                        TEST_ASSERT(is_err<desfire::error::app_integrity_error>(token.is_gate_enrolled(gid, false, false)));
                        // Moreover, also these will cascade-fail when we enable file checking!
                        TEST_ASSERT(is_err<desfire::error::app_integrity_error>(token.is_gate_enrolled(gid, false, true)));
                        TEST_ASSERT(is_err<desfire::error::app_integrity_error>(token.read_gate_file(gid, key, false, true)));
                        TEST_ASSERT(is_err<desfire::error::app_integrity_error>(token.is_gate_enrolled(gid, false, true)));
                        TEST_ASSERT(is_err<desfire::error::app_integrity_error>(token.read_encrypted_gate_file(g, false, true)));
                        TEST_ASSERT(is_err<desfire::error::app_integrity_error>(token.check_encrypted_gate_file(bundle.km, cfg, {}, false, true)));
                        suppress.restore();
                    }
                    // These pass if we do not check the app
                    TEST_ASSERT(is_err<desfire::error::permission_denied>(token.read_gate_file(gid, key, false, false)));
                    TEST_ASSERT(is_err<desfire::error::permission_denied>(token.write_gate_file(gid, mkey, {}, false)));
                    TEST_ASSERT(is_err<desfire::error::permission_denied>(token.write_encrypted_gate_file(bundle.km, cfg, {}, false)));
                    TEST_ASSERT(is_err<desfire::error::permission_denied>(token.read_encrypted_gate_file(g, false, false)));
                    TEST_ASSERT(is_err<desfire::error::permission_denied>(token.enroll_gate_key(gid, mkey, key, false)));
                    TEST_ASSERT(is_err<desfire::error::permission_denied>(token.check_encrypted_gate_file(bundle.km, cfg, {}, false, false)));

                    r_gate_apps = token.list_gate_apps(false);
                    TEST_ASSERT(r_gate_apps);
                    TEST_ASSERT(r_gate_apps->end() == ka::unpack_app_id(ka::pack_app_id(aid) + 1));
                }
                TEST_ASSERT(desfire::fs::login_app(token.tag(), desfire::root_app, rkey));
                TEST_ASSERT(token.tag().format_picc());
            }
        }
    }

    void test_file_ops() {
        TEST_ASSERT(instance.tag != nullptr);
        if (instance.tag == nullptr) {
            return;
        }

        member_token token{*instance.tag};

        const auto r_id = token.get_id();
        TEST_ASSERT(r_id);

        const auto rkey = bundle.kp.derive_token_root_key(*r_id);
        const auto mkey = bundle.kp.derive_gate_app_master_key(*r_id);
        TEST_ASSERT(ok_and<true>(token.check_root(rkey)));


        /**
         * Create a fully working gate
         */
        const auto &g = bundle.g0;
        const auto gid = bundle.g0.id();
        const auto &cfg = bundle.g0_cfg;
        const gate_token_key key = bundle.g0.app_base_key().derive_token_key(*r_id, gid.key_no());

        TEST_ASSERT(token.ensure_gate_app(gate_id::first_aid, rkey, mkey));
        TEST_ASSERT(token.enroll_gate_key(gid, mkey, key, true));

        /**
         * Test that reading fails with file_not_found independently of checking
         */
        {
            TEST_ASSERT(is_err<desfire::error::file_not_found>(token.read_master_file(mkey, false, true)));
            TEST_ASSERT(is_err<desfire::error::file_not_found>(token.read_master_file(mkey, false, false)));
            TEST_ASSERT(is_err<desfire::error::file_not_found>(token.read_gate_file(gid, key, false, true)));
            TEST_ASSERT(is_err<desfire::error::file_not_found>(token.read_gate_file(gid, key, false, false)));
            TEST_ASSERT(is_err<desfire::error::file_not_found>(token.read_encrypted_master_file(bundle.km, false, true)));
            TEST_ASSERT(is_err<desfire::error::file_not_found>(token.read_encrypted_master_file(bundle.km, false, false)));
            TEST_ASSERT(is_err<desfire::error::file_not_found>(token.read_encrypted_gate_file(g, false, true)));
            TEST_ASSERT(is_err<desfire::error::file_not_found>(token.read_encrypted_gate_file(g, false, false)));

            TEST_ASSERT(is_err<desfire::error::file_not_found>(token.check_gate_file(gid, false, false)));
            TEST_ASSERT(is_err<desfire::error::file_not_found>(token.check_master_file(false, false)));

            TEST_ASSERT(ok_and<false>(token.is_gate_enrolled(gid, false, true)));
            TEST_ASSERT(ok_and<false>(token.is_master_enrolled(false, true)));
            TEST_ASSERT(is_err<desfire::error::file_not_found>(token.is_gate_enrolled_correctly(bundle.km, cfg)));
            TEST_ASSERT(ok_and<false>(token.is_master_enrolled(false, true)));
            TEST_ASSERT(is_err<desfire::error::file_not_found>(token.is_deployed_correctly(bundle.km)));
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
                    ESP_LOGI("TEST", "Testing invalid master std file settings: "
                                     "sec=%s, rw=%c, chg=%c, r=%c, w=%c",
                             desfire::to_string(settings.common_settings().security),
                             settings.common_settings().rights.read_write.describe(),
                             settings.common_settings().rights.change.describe(),
                             settings.common_settings().rights.read.describe(),
                             settings.common_settings().rights.write.describe());
                } else {
                    ESP_LOGI("TEST", "Testing invalid master file type.");
                }

                TEST_ASSERT(desfire::fs::login_app(token.tag(), aid, mkey));
                TEST_ASSERT(token.tag().create_file(0x00, settings));

                desfire::esp32::suppress_log suppress{"KA"};
                TEST_ASSERT(is_err<desfire::error::file_integrity_error>(token.read_master_file(mkey, false, true)));
                TEST_ASSERT(is_err<desfire::error::file_integrity_error>(token.read_encrypted_master_file(bundle.km, false, true)));

                if (settings.common_settings().security != file_security::encrypted or
                    settings.common_settings().rights.read != 0_b or
                    settings.type() != file_type::standard) {
                    TEST_ASSERT(is_err<desfire::error::file_integrity_error>(token.read_master_file(mkey, false, false)));
                    TEST_ASSERT(is_err<desfire::error::file_integrity_error>(token.read_encrypted_master_file(bundle.km, false, false)));
                } else {
                    // This one passes
                    TEST_ASSERT(token.read_master_file(mkey, false, false));
                    TEST_ASSERT(is_err<desfire::error::crypto_error>(token.read_encrypted_master_file(bundle.km, false, false)));
                }

                TEST_ASSERT(ok_and<false>(token.check_master_file(false, false)));
                TEST_ASSERT(is_err<desfire::error::file_integrity_error>(token.is_master_enrolled(false, true)));
                // This one passes
                TEST_ASSERT(ok_and<true>(token.is_master_enrolled(false, false)));
                TEST_ASSERT(is_err<desfire::error::file_integrity_error>(token.is_deployed_correctly(bundle.km)));

                TEST_ASSERT(desfire::fs::login_app(token.tag(), aid, mkey));
                TEST_ASSERT(token.tag().delete_file(0x00));
            }

            /**
             * We need an actual master file to test at a gate file level
             */
            TEST_ASSERT(token.write_encrypted_master_file(bundle.km, bundle.id, true));
            const auto r_identity = token.read_encrypted_master_file(bundle.km, true, true);
            TEST_ASSERT(r_identity);
            TEST_ASSERT(r_identity->first == bundle.id);
            TEST_ASSERT(ok_and<true>(token.is_master_enrolled(true, true)));
            TEST_ASSERT(token.is_deployed_correctly(bundle.km));

            for (auto const &settings : invalid_gate_settings) {
                if (settings.type() == file_type::standard) {
                    ESP_LOGI("TEST", "Testing invalid std file settings: "
                                     "sec=%s, rw=%c, chg=%c, r=%c, w=%c",
                             desfire::to_string(settings.common_settings().security),
                             settings.common_settings().rights.read_write.describe(),
                             settings.common_settings().rights.change.describe(),
                             settings.common_settings().rights.read.describe(),
                             settings.common_settings().rights.write.describe());
                } else {
                    ESP_LOGI("TEST", "Testing invalid file type.");
                }

                TEST_ASSERT(desfire::fs::login_app(token.tag(), aid, mkey));
                TEST_ASSERT(token.tag().create_file(fid, settings));

                desfire::esp32::suppress_log suppress{"KA"};
                TEST_ASSERT(is_err<desfire::error::file_integrity_error>(token.read_gate_file(gid, key, false, true)));
                TEST_ASSERT(is_err<desfire::error::file_integrity_error>(token.read_encrypted_gate_file(g, false, true)));

                if (settings.common_settings().security != file_security::encrypted or
                    settings.common_settings().rights.read != gid.key_no() or
                    settings.type() != file_type::standard) {
                    TEST_ASSERT(is_err<desfire::error::file_integrity_error>(token.read_gate_file(gid, key, false, false)));
                    TEST_ASSERT(is_err<desfire::error::file_integrity_error>(token.read_encrypted_gate_file(g, false, false)));
                } else {
                    // This one passes
                    TEST_ASSERT(token.read_gate_file(gid, key, false, false));
                    TEST_ASSERT(is_err<desfire::error::crypto_error>(token.read_encrypted_gate_file(g, false, false)));
                }

                TEST_ASSERT(ok_and<false>(token.check_gate_file(gid, false, false)));
                TEST_ASSERT(is_err<desfire::error::file_integrity_error>(token.is_gate_enrolled(gid, false, true)));
                // This one passes
                TEST_ASSERT(ok_and<true>(token.is_gate_enrolled(gid, false, false)));
                TEST_ASSERT(is_err<desfire::error::file_integrity_error>(token.is_gate_enrolled_correctly(bundle.km, cfg)));

                // Also this one
                auto r_list = token.list_gates(false, false);
                TEST_ASSERT(r_list);
                TEST_ASSERT(r_list->size() == 1 and r_list->front() == gid);

                r_list = token.list_gates(false, true);
                TEST_ASSERT(r_list);
                TEST_ASSERT(r_list->empty());


                TEST_ASSERT(desfire::fs::login_app(token.tag(), aid, mkey));
                TEST_ASSERT(token.tag().delete_file(fid));
            }
        }

        /**
         * Now make sure that real gate enrollment works.
         */
        {
            // Note: a key is already enrolled, so this tests that re-enrolling works correctly
            const ka::identity fake_identity{{}, "Not me", {}};

            TEST_ASSERT(token.write_encrypted_gate_file(bundle.km, cfg, fake_identity, true));
            TEST_ASSERT(ok_and<true>(token.is_gate_enrolled(gid, true, true)));
            TEST_ASSERT(ok_and<true>(token.check_gate_file(gid, true, true)));
            TEST_ASSERT(token.read_gate_file(gid, key, true, true));
            TEST_ASSERT(token.read_encrypted_gate_file(g, true, true));

            // Fake identity: must fail the "correctly" check
            TEST_ASSERT(ok_and<false>(token.is_gate_enrolled_correctly(bundle.km, cfg)));

            auto r_list = token.list_gates(true, true);
            TEST_ASSERT(r_list);
            TEST_ASSERT(r_list->size() == 1 and r_list->front() == gid);

            // Attempting to enroll a fake identity should trigger parm error at this stage!
            TEST_ASSERT(is_err<desfire::error::parameter_error>(token.enroll_gate(bundle.km, cfg, fake_identity)));

            // Right, let's do this with the correct identity
            TEST_ASSERT(token.write_encrypted_gate_file(bundle.km, cfg, bundle.id, true));
            TEST_ASSERT(ok_and<true>(token.is_gate_enrolled_correctly(bundle.km, cfg)));

            // Let's assert that the top-level enrollment works too
            TEST_ASSERT(token.enroll_gate(bundle.km, cfg, bundle.id));

            // And finally let us assert that listing the gates includes the one we just got
            r_list = token.list_gates(true, true);
            TEST_ASSERT(r_list);
            TEST_ASSERT(r_list->size() == 1 and r_list->front() == gid);
        }
    }

    void test_nvs() {
        // Make sure nvs is initialized
        auto &nvs = nvs::instance();

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
        ESP_LOGI("TEST", "nvs     free entries: %d", stats.free_entries);
        ESP_LOGI("TEST", "nvs  namespace count: %d", stats.namespace_count);
        ESP_LOGI("TEST", "nvs     used entries: %d", stats.used_entries);
        ESP_LOGI("TEST", "nvs    total entries: %d", stats.total_entries);
        ESP_LOGI("TEST", "nvs::ka used entries: %d", ns->used_entries());
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

    void test_regular_flow() {
        TEST_ASSERT(instance.tag != nullptr);
        if (instance.tag == nullptr) {
            return;
        }

        member_token token{*instance.tag};

        const auto r_id = token.get_id();
        TEST_ASSERT(r_id);

        const auto rkey = bundle.kp.derive_token_root_key(*r_id);
        TEST_ASSERT(ok_and<true>(token.check_root(rkey)));

        TEST_ASSERT(token.tag().format_picc());

        TEST_ASSERT(is_err<desfire::error::app_not_found>(token.is_deployed_correctly(bundle.km)));
        TEST_ASSERT(ok_and<false>(token.is_master_enrolled(true, true)));

        TEST_ASSERT(token.deploy(bundle.km, bundle.id));
        TEST_ASSERT(ok_and<true>(token.is_master_enrolled(true, true)));
        TEST_ASSERT(token.is_deployed_correctly(bundle.km));

        TEST_ASSERT(ok_and<false>(token.is_gate_enrolled(bundle.g0.id(), true, true)));
        TEST_ASSERT(is_err<desfire::error::file_not_found>(token.is_gate_enrolled_correctly(bundle.km, bundle.g0_cfg)));
        TEST_ASSERT(token.enroll_gate(bundle.km, bundle.g0_cfg, bundle.id));
        TEST_ASSERT(ok_and<true>(token.is_master_enrolled(true, true)));

        TEST_ASSERT(token.is_deployed_correctly(bundle.km));
        TEST_ASSERT(ok_and<true>(token.is_gate_enrolled(bundle.g0.id(), true, true)));
        TEST_ASSERT(token.is_gate_enrolled_correctly(bundle.km, bundle.g0_cfg));

        // Does it work twice in a row?
        TEST_ASSERT(token.enroll_gate(bundle.km, bundle.g0_cfg, bundle.id));
        TEST_ASSERT(ok_and<true>(token.is_master_enrolled(true, true)));

        TEST_ASSERT(token.is_deployed_correctly(bundle.km));
        TEST_ASSERT(ok_and<true>(token.is_gate_enrolled(bundle.g0.id(), true, true)));
        TEST_ASSERT(token.is_gate_enrolled_correctly(bundle.km, bundle.g0_cfg));

        // Does it access?
        const auto r_gate_id = token.read_encrypted_gate_file(bundle.g0, true, true);
        TEST_ASSERT(r_gate_id);
        const auto r_master_id = token.read_encrypted_master_file(bundle.km, true, true);
        TEST_ASSERT(r_master_id);
        TEST_ASSERT(*r_gate_id == *r_master_id);

        // Benchmark reading the gate file
        ESP_LOGI("TEST", "Benchmarking read_encrypted_gate_file...");
        static constexpr auto n_tests = 20;
        mlab::timer t;
        for (std::size_t i = 0; i < n_tests; ++i) {
            TEST_ASSERT(token.read_encrypted_gate_file(bundle.g0, true, true));
        }
        const auto elapsed = t.elapsed();
        ESP_LOGI("TEST", "Benchmark ended, average time: %0.f ms.", double(elapsed.count()) / n_tests);

        // Does it work with a different gate app?
        TEST_ASSERT(ok_and<false>(token.is_gate_enrolled(bundle.g13.id(), true, true)));
        TEST_ASSERT(is_err<desfire::error::app_not_found>(token.is_gate_enrolled_correctly(bundle.km, bundle.g13_cfg)));
        TEST_ASSERT(token.enroll_gate(bundle.km, bundle.g13_cfg, bundle.id));
        TEST_ASSERT(ok_and<true>(token.is_master_enrolled(true, true)));

        TEST_ASSERT(token.is_deployed_correctly(bundle.km));
        TEST_ASSERT(ok_and<true>(token.is_gate_enrolled(bundle.g13.id(), true, true)));
        TEST_ASSERT(token.is_gate_enrolled_correctly(bundle.km, bundle.g13_cfg));

        // Does it work twice in a row?
        TEST_ASSERT(token.enroll_gate(bundle.km, bundle.g13_cfg, bundle.id));
        TEST_ASSERT(ok_and<true>(token.is_master_enrolled(true, true)));

        TEST_ASSERT(token.is_deployed_correctly(bundle.km));
        TEST_ASSERT(ok_and<true>(token.is_gate_enrolled(bundle.g13.id(), true, true)));
        TEST_ASSERT(token.is_gate_enrolled_correctly(bundle.km, bundle.g13_cfg));
    }
}// namespace ut

extern "C" void app_main() {
    UNITY_BEGIN();

    RUN_TEST(ut::test_keys);
    RUN_TEST(ut::test_nvs);
    RUN_TEST(ut::test_encrypt_decrypt);

    ESP_LOGI("TEST", "Attempting to set up a PN532 on pins %d, %d", pinout::pn532_hsu_rx, pinout::pn532_hsu_tx);

    /**
     * @note When running on the CI/CD machine, we need to make sure we are on HSU
     */
    if constexpr (pinout::supports_cicd_machine) {
        gpio_set_direction(pinout::pn532_cicd_rstn, GPIO_MODE_OUTPUT);
        gpio_set_direction(pinout::pn532_cicd_i0, GPIO_MODE_OUTPUT);
        gpio_set_direction(pinout::pn532_cicd_i1, GPIO_MODE_OUTPUT);
        // Power cycle the pn532
        gpio_set_level(pinout::pn532_cicd_rstn, 0);
        std::this_thread::sleep_for(500ms);
        gpio_set_level(pinout::pn532_cicd_i0, 0);
        gpio_set_level(pinout::pn532_cicd_i1, 0);
        gpio_set_level(pinout::pn532_cicd_rstn, 1);
        std::this_thread::sleep_for(500ms);
    }

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
                ESP_LOG_BUFFER_HEX_LEVEL("TEST", target.nfcid.data(), target.nfcid.size(), ESP_LOG_INFO);
                std::copy_n(std::begin(target.nfcid), ut::instance.nfc_id.size(), std::begin(ut::instance.nfc_id));
                ut::instance.tag = std::make_unique<desfire::tag>(
                        desfire::tag::make<desfire::esp32::default_cipher_provider>(*ut::instance.controller, target.logical_index));
                // We only need one
                break;
            }
        }

        if (ut::instance.tag == nullptr) {
            ESP_LOGE("TEST", "Could not find any tag!");
        }

        RUN_TEST(ut::test_tag_reset_root_key_and_format);
        RUN_TEST(ut::test_root_ops);
        RUN_TEST(ut::test_app_ops);
        RUN_TEST(ut::test_file_ops);
        RUN_TEST(ut::test_regular_flow);

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
        if constexpr (std::is_same_v<std::remove_const_t<std::remove_reference_t<decltype(*res)>>, bool>) {
            return res and *res == B;
        } else {
            return res and res->first == B;
        }
    }

    template <desfire::error E, class Result>
    bool is_err(Result const &res) {
        return not res and res.error() == E;
    }

}// namespace ut