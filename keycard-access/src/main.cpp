#include "desfire/esp32/utils.hpp"
#include <esp_log.h>
#include <freertos/FreeRTOS.h>
#include <freertos/task.h>
#include <ka/config.hpp>
#include <ka/gate.hpp>
#include <ka/p2p_ops.hpp>
#include <pn532/controller.hpp>
#include <pn532/esp32/hsu.hpp>
#include <ka/desfire_fs.hpp>

using namespace std::chrono_literals;

void gate_main() {
    pn532::esp32::hsu_channel hsu_chn{ka::pinout::uart_port, ka::pinout::uart_config, ka::pinout::pn532_hsu_tx, ka::pinout::pn532_hsu_rx};
    pn532::controller controller{hsu_chn};
    pn532::scanner scanner{controller};

    ESP_LOGI("KA", "Loading configuration.");
    ka::gate gate = ka::gate::load_from_config();

    if (not scanner.init_and_test_controller()) {
        ESP_LOGE("KA", "Power cycle the device to try again.");
        return;
    }

    ESP_LOGI("KA", "Self-test passed.");

    if (not gate.is_configured()) {
        ESP_LOGW("KA", "Gate is not configured, entering target mode.");
        ka::p2p::configure_gate_loop(controller, gate);
        gate.config_store();
        ESP_LOGI("KA", "Gate configured.");
    }

    ESP_LOGI("KA", "Gate %d \"%s\".", gate.id(), gate.description().c_str());
    ESP_LOGI("KA", "Gate public key:");
    ESP_LOG_BUFFER_HEX_LEVEL("KA", gate.keys().raw_pk().data(), ka::raw_pub_key::array_size, ESP_LOG_INFO);
    ESP_LOGI("KA", "Keymaker public key:");
    ESP_LOG_BUFFER_HEX_LEVEL("KA", gate.programmer_pub_key().raw_pk().data(), ka::raw_pub_key::array_size, ESP_LOG_INFO);

    ka::gate_responder responder{gate};
    scanner.loop(responder, false /* already performed */);
}

struct format_mcformatface final : public desfire::tag_responder<desfire::esp32::default_cipher_provider> {
    ka::token_id current_id{};

    void get_scan_target_types(pn532::scanner &, std::vector<pn532::target_type> &targets) const override {
        targets = pn532::controller::poll_all_targets;
    }

    void on_activation(pn532::scanner &, pn532::scanned_target const &target) override {
        const auto s_id = ka::util::hex_string(mlab::make_range(target.nfcid.data(), target.nfcid.data() + target.nfcid.size()));
        ESP_LOGI("NFC", "Activated: %s target %s.", pn532::to_string(target.type), s_id.c_str());
    }

    void on_release(pn532::scanner &, pn532::scanned_target const &target) override {
        const auto s_id = ka::util::hex_string(mlab::make_range(target.nfcid.data(), target.nfcid.data() + target.nfcid.size()));
        ESP_LOGI("NFC", "Released: %s target %s.", pn532::to_string(target.type), s_id.c_str());
    }

    void on_leaving_rf(pn532::scanner &, pn532::scanned_target const &target) override {
        const auto s_id = ka::util::hex_string(mlab::make_range(target.nfcid.data(), target.nfcid.data() + target.nfcid.size()));
        ESP_LOGI("NFC", "Out of RF: %s target %s.", pn532::to_string(target.type), s_id.c_str());
    }

    void on_failed_scan(pn532::scanner &, pn532::channel::error err) override {
        ESP_LOGW("NFC", "Failed scan: %s", pn532::to_string(err));
    }

    pn532::post_interaction interact(pn532::scanner &scanner, pn532::scanned_target const &target) override {
        current_id = ka::util::id_from_nfc_id(target.nfcid);
        return desfire::tag_responder<desfire::esp32::default_cipher_provider>::interact(scanner, target);
    }

    static constexpr std::uint8_t secondary_keys_version = 0x10;
    static constexpr std::array<std::uint8_t, 8> secondary_des_key = {0x0, 0x2, 0x4, 0x6, 0x8, 0xa, 0xc, 0xe};
    static constexpr std::array<std::uint8_t, 16> secondary_des3_2k_key = {0x0, 0x2, 0x4, 0x6, 0x8, 0xa, 0xc, 0xe, 0x10, 0x12, 0x14, 0x16, 0x18, 0x1a, 0x1c, 0x1e};
    static constexpr std::array<std::uint8_t, 24> secondary_des3_3k_key = {0x0, 0x2, 0x4, 0x6, 0x8, 0xa, 0xc, 0xe, 0x10, 0x12, 0x14, 0x16, 0x18, 0x1a, 0x1c, 0x1e, 0x20, 0x22, 0x24, 0x26, 0x28, 0x2a, 0x2c, 0x2e};
    static constexpr std::array<std::uint8_t, 16> secondary_aes_key = {0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0xa, 0xb, 0xc, 0xd, 0xe, 0xf};

    [[nodiscard]] static ka::key_pair &test_key_pair() {
        static ka::key_pair _kp{{
                0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
                0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f
        }};
        return _kp;
    }

    [[nodiscard]] static ka::key_pair &demo_key_pair() {
        static ka::key_pair _kp{ka::pwhash, "foobar"};
        return _kp;
    }

    desfire::tag::result<> interact_with_tag_internal(desfire::tag &tag) const {
        const desfire::any_key default_k{desfire::cipher_type::des};
        const std::vector<desfire::any_key> keys_to_test = {
                    default_k,
                    test_key_pair().derive_token_root_key(current_id),
                    demo_key_pair().derive_token_root_key(current_id),
                    desfire::any_key{desfire::cipher_type::des3_2k},
                    desfire::any_key{desfire::cipher_type::des3_3k},
                    desfire::any_key{desfire::cipher_type::aes128},
                    desfire::any_key{desfire::cipher_type::des, mlab::make_range(secondary_des_key), 0, secondary_keys_version},
                    desfire::any_key{desfire::cipher_type::des3_2k, mlab::make_range(secondary_des3_2k_key), 0, secondary_keys_version},
                    desfire::any_key{desfire::cipher_type::des3_3k, mlab::make_range(secondary_des3_3k_key), 0, secondary_keys_version},
                    desfire::any_key{desfire::cipher_type::aes128, mlab::make_range(secondary_aes_key), 0, secondary_keys_version}};
        const auto s_nfcid = ka::util::hex_string(current_id);
        ESP_LOGI("KA", "Attempting to recover root key for ID %s", s_nfcid.c_str());
        TRY(tag.select_application());
        for (auto const &key : keys_to_test) {
            auto suppress = desfire::esp32::suppress_log{DESFIRE_LOG_PREFIX};
            if (tag.authenticate(key)) {
                suppress.restore();
                ESP_LOGI("KA", "Found the right key, changing to default.");
                TRY(tag.change_key(default_k));
                TRY(tag.authenticate(default_k));
                ESP_LOGI("KA", "NFC ID: %s", s_nfcid.c_str());
                TRY_RESULT(tag.get_info()) {
                    const auto s_serial = ka::util::hex_string(r->serial_no);
                    ESP_LOGI("KA", "Serial: %s", s_nfcid.c_str());
                }
                TRY_RESULT(tag.get_card_uid()) {
                    const auto s_card_uid = ka::util::hex_string(*r);
                    ESP_LOGI("KA", "CardID: %s", s_nfcid.c_str());
                }
                TRY_RESULT(tag.get_application_ids()) {
                    ESP_LOGI("KA", "  Apps: %d", r->size());
                    for (std::size_t i = 0; i < r->size(); ++i) {
                        ESP_LOGI("KA", "       %2d. %02x%2x%2x", i + 1, (*r)[i][0], (*r)[i][1], (*r)[i][2]);
                    }
                }
                TRY(tag.format_picc());
                ESP_LOGI("KA", "Formatted.");
                return mlab::result_success;
            }
        }
        ESP_LOGE("KA", "I do not know the key...");
        return mlab::result_success;
    }

    pn532::post_interaction interact_with_tag(desfire::tag &tag) override {
        ESP_LOGI("KA", "Beginning interaction.");
        const auto success = bool(interact_with_tag_internal(tag));
        ESP_LOG_LEVEL_LOCAL((success ? ESP_LOG_INFO : ESP_LOG_WARN), "KA", "Interaction complete.");
        return pn532::post_interaction::reject;
    }
};


struct keymaker_responder final : public ka::member_token_responder {
    ka::keymaker km;

    keymaker_responder() : km{} {
        km._kp.generate_from_pwhash("foobar");
    }

    void get_scan_target_types(pn532::scanner &, std::vector<pn532::target_type> &targets) const override {
        // Allow both DEP targets (gates to be configured) and Mifare targets
        targets = {pn532::target_type::dep_passive_424kbps, pn532::target_type::dep_passive_212kbps, pn532::target_type::dep_passive_106kbps,
                   pn532::target_type::passive_106kbps_iso_iec_14443_4_typea};
    }

    pn532::post_interaction interact(pn532::scanner &scanner, pn532::scanned_target const &target) override {
        const auto s_nfcid = ka::util::hex_string(mlab::make_range(target.nfcid.data(), target.nfcid.data() + target.nfcid.size()));
        ESP_LOGI("KA", "Found %s target with NFC ID %s.", pn532::to_string(target.type), s_nfcid.c_str());
        if (target.type == pn532::target_type::passive_106kbps_iso_iec_14443_4_typea) {
            return desfire::tag_responder<desfire::esp32::default_cipher_provider>::interact(scanner, target);
        } else {
            // Enter a gate configuration loop
            if (ka::p2p::configure_gate_in_rf(scanner.ctrl(), target.index, km, "Dummy gate")) {
                ESP_LOGI("KA", "Gate configured.");
            } else {
                ESP_LOGE("KA", "Gate not configured.");
            }
        }
        return pn532::post_interaction::reject;
    }

    desfire::tag::result<> interact_with_token_internal(ka::member_token &token) {
        desfire::esp32::suppress_log suppress{"KA", DESFIRE_FS_DEFAULT_LOG_PREFIX, DESFIRE_DEFAULT_LOG_PREFIX};
        TRY_RESULT_AS(token.get_id(), r_id) {
            const auto root_key = km.keys().derive_token_root_key(*r_id);
            suppress.restore();
            const std::string id_str = ka::util::hex_string(*r_id);
            ESP_LOGI("KA", "Got the following token: %s.", id_str.c_str());
            suppress.suppress();
            if (token.unlock_root()) {
                suppress.restore();
                ESP_LOGI("KA", "Empty token, setting up MAD.");
                TRY(token.tag().format_picc())
                TRY(token.setup_root(root_key))
                TRY(token.setup_mad(ka::identity{*r_id, "Holder", "Publisher"}))
            } else if (token.try_set_root_key(root_key)) {
                suppress.restore();
                ESP_LOGI("KA", "Token was set up.");
                suppress.suppress();
                if (const auto r_identity = token.get_identity(); r_identity) {
                    suppress.restore();
                    ESP_LOGI("KA", "MAD was set up for user %s (%s).", r_identity->holder.c_str(), r_identity->publisher.c_str());
                    ESP_LOGW("KA", "We are now trusting this data, during regular operation, it should be authenticated!");
                    ESP_LOGI("KA", "Setting up gates.");
                    bool all_enrolled = true;
                    for (ka::gate_config const &cfg : km._gates) {
                        if (token.is_gate_enrolled(cfg.id)) {
                            ESP_LOGI("KA", "Gate %d was already enrolled.", cfg.id);
                        } else {
                            all_enrolled = false;
                            TRY(token.enroll_gate(cfg.id, cfg.app_base_key.derive_app_master_key(*r_id), *r_identity))
                            ESP_LOGI("KA", "I just enrolled gate %d", cfg.id);
                        }
                    }
                    if (all_enrolled) {
                        ESP_LOGI("KA", "All gates enrolled, I'll format this PICC.");
                        TRY(token.unlock_root())
                        /**
                         * @todo Formatting seems to have no effect, is the whole thing running correctly?
                         */
                        TRY(token.tag().format_picc())
                        TRY(token.unlock_root())
                        TRY(token.tag().change_key(desfire::key<desfire::cipher_type::des>{}))
                    }
                } else {
                    suppress.restore();
                    ESP_LOGW("KA", "MAD was not set up, will format the PICC.");
                    TRY(token.unlock_root())
                    /**
                     * @todo Formatting seems to have no effect, is the whole thing running correctly?
                     */
                    TRY(token.tag().format_picc())
                    TRY(token.unlock_root())
                    TRY(token.tag().change_key(desfire::key<desfire::cipher_type::des>{}))
                }
            }
        }
        return mlab::result_success;
    }

    pn532::post_interaction interact_with_token(ka::member_token &token) override {
        interact_with_token_internal(token);
        ESP_LOGI("KA", "Interaction complete.");
        return pn532::post_interaction::reject;
    }
};

void keymaker_main() {
    pn532::esp32::hsu_channel hsu_chn{ka::pinout::uart_port, ka::pinout::uart_config, ka::pinout::pn532_hsu_tx, ka::pinout::pn532_hsu_rx};
    pn532::controller controller{hsu_chn};
    pn532::scanner scanner{controller};

    keymaker_responder responder{};

    if (not scanner.init_and_test_controller()) {
        ESP_LOGE("KA", "Power cycle the device to try again.");
        return;
    }

    ESP_LOGI("KA", "Self-test passed.");
    scanner.loop(responder, false /* already performed */);
}

void format_mcformatface_main() {
    pn532::esp32::hsu_channel hsu_chn{ka::pinout::uart_port, ka::pinout::uart_config, ka::pinout::pn532_hsu_tx, ka::pinout::pn532_hsu_rx};
    pn532::controller controller{hsu_chn};
    pn532::scanner scanner{controller};

    format_mcformatface responder{};

    if (not scanner.init_and_test_controller()) {
        ESP_LOGE("KA", "Power cycle the device to try again.");
        return;
    }

    ESP_LOGI("KA", "Self-test passed.");
    scanner.loop(responder, false /* already performed */);
}

extern "C" void app_main() {
    desfire::esp32::suppress_log suppress{"AUTH ROOT KEY"};
    ESP_LOGI("KA", "Waiting 2s to ensure the serial is attached and visible...");
    vTaskDelay(pdMS_TO_TICKS(2000));
    int choice = 0;
    while (choice == 0) {
        std::printf("Select operation mode of the demo:\n");
        std::printf("\t1. gate\n");
        std::printf("\t2. keymaker\n");
        std::printf("\t3. FormatMcFormatface\n");
        std::printf("> ");
        while (std::scanf("%d", &choice) != 1) {
            vTaskDelay(pdMS_TO_TICKS(100));
        }
        if (choice < 1 or choice > 3) {
            std::printf("Insert '1' or '2' or '3'.");
            choice = 0;
        }
    }
    std::printf("\n");
    switch (choice) {
        case 1:
            std::printf("Acting as gate.\n");
            gate_main();
            break;
        case 2:
            std::printf("Acting as keymaker.\n");
            keymaker_main();
            break;
        case 3:
            std::printf("Enter... Format McFormatface\n");
            format_mcformatface_main();
            break;
        default:
            break;
    }
    vTaskSuspend(nullptr);
}
