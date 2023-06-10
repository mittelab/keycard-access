#include <desfire/esp32/utils.hpp>
#include <esp_log.h>
#include <freertos/FreeRTOS.h>
#include <freertos/task.h>
#include <ka/config.hpp>
#include <ka/gate.hpp>
#include <ka/ota.hpp>
#include <ka/p2p_ops.hpp>
#include <ka/wifi.hpp>
#include <mlab/strutils.hpp>
#include <pn532/controller.hpp>
#include <pn532/esp32/hsu.hpp>


// Override the log prefix
#define LOG_PFX "KADEMO"
#define DESFIRE_FS_LOG_PREFIX LOG_PFX
#include <desfire/fs.hpp>

using namespace std::chrono_literals;

struct format_mcformatface final : public desfire::tag_responder<desfire::esp32::default_cipher_provider> {
    ka::token_id current_id{};

    void on_activation(pn532::scanner &, pn532::scanned_target const &target) override {
        const auto s_id = mlab::data_to_hex_string(target.nfcid);
        ESP_LOGI("NFC", "Activated: %s target %s.", pn532::to_string(target.type), s_id.c_str());
    }

    void on_release(pn532::scanner &, pn532::scanned_target const &target) override {
        const auto s_id = mlab::data_to_hex_string(target.nfcid);
        ESP_LOGI("NFC", "Released: %s target %s.", pn532::to_string(target.type), s_id.c_str());
    }

    void on_leaving_rf(pn532::scanner &, pn532::scanned_target const &target) override {
        const auto s_id = mlab::data_to_hex_string(target.nfcid);
        ESP_LOGI("NFC", "Out of RF: %s target %s.", pn532::to_string(target.type), s_id.c_str());
    }

    void on_failed_scan(pn532::scanner &, pn532::channel_error err) override {
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
        static ka::key_pair _kp{{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
                                 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f}};
        return _kp;
    }

    [[nodiscard]] static ka::key_pair &demo_key_pair() {
        static ka::key_pair _kp{ka::pwhash, "foobar"};
        return _kp;
    }

    desfire::result<> interact_with_tag_internal(desfire::tag &tag) const {
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
        const auto s_nfcid = mlab::data_to_hex_string(current_id);
        ESP_LOGI(LOG_PFX, "Attempting to recover root key for ID %s", s_nfcid.c_str());
        TRY(tag.select_application());
        for (auto const &key : keys_to_test) {
            const auto key_body = key.get_packed_key_body();
            const auto s_key_body = mlab::data_to_hex_string(key_body);
            ESP_LOGI(LOG_PFX, "Trying %s...", s_key_body.c_str());
            auto suppress = desfire::esp32::suppress_log{DESFIRE_LOG_PREFIX};
            if (tag.authenticate(key)) {
                suppress.restore();
                ESP_LOGI(LOG_PFX, "Found the right key, changing to default.");
                TRY(tag.change_key(default_k));
                TRY(tag.authenticate(default_k));
                ESP_LOGI(LOG_PFX, "NFC ID: %s", s_nfcid.c_str());
                TRY_RESULT(tag.get_info()) {
                    const auto s_serial = mlab::data_to_hex_string(r->serial_no);
                    ESP_LOGI(LOG_PFX, "Serial: %s", s_nfcid.c_str());
                }
                TRY_RESULT(tag.get_card_uid()) {
                    const auto s_card_uid = mlab::data_to_hex_string(*r);
                    ESP_LOGI(LOG_PFX, "CardID: %s", s_nfcid.c_str());
                }
                TRY_RESULT(tag.get_application_ids()) {
                    if (r->empty()) {
                        ESP_LOGI(LOG_PFX, "  Apps: none");
                    } else {
                        for (std::size_t i = 0; i < r->size(); ++i) {
                            ESP_LOGI(LOG_PFX, "  %s %2d. %02x%2x%2x", (i == 0 ? "Apps:" : "     "), i + 1, (*r)[i][0], (*r)[i][1], (*r)[i][2]);
                        }
                    }
                }
                TRY(tag.format_picc());
                ESP_LOGI(LOG_PFX, "Formatted.");
                return mlab::result_success;
            }
        }
        ESP_LOGE(LOG_PFX, "I do not know the key...");
        return mlab::result_success;
    }

    pn532::post_interaction interact_with_tag(desfire::tag &tag) override {
        ESP_LOGI(LOG_PFX, "Beginning interaction.");
        const auto success = bool(interact_with_tag_internal(tag));
        ESP_LOG_LEVEL_LOCAL((success ? ESP_LOG_INFO : ESP_LOG_WARN), LOG_PFX, "Interaction complete.");
        return pn532::post_interaction::reject;
    }
};

struct keymaker_responder final : public ka::member_token_responder {
    ka::keymaker km;

    keymaker_responder() : km{} {
        km._kp.generate_from_pwhash("foobar");
    }

    std::vector<pn532::target_type> get_scan_target_types(pn532::scanner &) const override {
        // Allow both DEP targets (gates to be configured) and Mifare targets
        return {pn532::target_type::dep_passive_424kbps, pn532::target_type::dep_passive_212kbps, pn532::target_type::dep_passive_106kbps,
                pn532::target_type::passive_106kbps_iso_iec_14443_4_typea};
    }

    pn532::post_interaction interact(pn532::scanner &scanner, pn532::scanned_target const &target) override {
        const auto s_nfcid = mlab::data_to_hex_string(target.nfcid);
        ESP_LOGI(LOG_PFX, "Found %s target with NFC ID %s.", pn532::to_string(target.type), s_nfcid.c_str());
        if (target.type == pn532::target_type::passive_106kbps_iso_iec_14443_4_typea) {
            return desfire::tag_responder<desfire::esp32::default_cipher_provider>::interact(scanner, target);
        } else {
            // Enter a gate configuration loop
            if (ka::p2p::configure_gate_in_rf(scanner.ctrl(), target.index, km, "Dummy gate")) {
                ESP_LOGI(LOG_PFX, "Gate configured.");
            } else {
                ESP_LOGE(LOG_PFX, "Gate not configured.");
            }
        }
        return pn532::post_interaction::reject;
    }

    desfire::result<> interact_with_token_internal(ka::member_token &token) {
        const ka::identity unique_id{{}, "Holder", "Publisher"};
        if (const auto r_deployed = token.is_deployed_correctly(km); r_deployed) {
            ESP_LOGI(LOG_PFX, "Token was deployed.");
            bool all_gates_were_enrolled = true;
            for (ka::gate_config const &cfg : km._gates) {
                if (const auto r_enrolled = token.is_gate_enrolled_correctly(km, cfg); r_enrolled) {
                    if (r_enrolled->first) {
                        ESP_LOGI(LOG_PFX, "Gate %lu was already enrolled.", std::uint32_t(cfg.id));
                        continue;
                    }
                } else if (r_enrolled.error() != desfire::error::app_not_found and
                           r_enrolled.error() != desfire::error::file_not_found) {
                    if (ka::member_token::has_custom_meaning(r_enrolled.error())) {
                        ESP_LOGW(LOG_PFX, "Invalid gate enrollment: %s", ka::member_token::describe(r_enrolled.error()));
                        continue;
                    }
                    return r_enrolled.error();
                }
                all_gates_were_enrolled = false;
                TRY(token.enroll_gate(km, cfg, unique_id))
                ESP_LOGI(LOG_PFX, "I just enrolled gate %lu", std::uint32_t(cfg.id));
            }
            if (all_gates_were_enrolled) {
                ESP_LOGI(LOG_PFX, "All gates were already enrolled, I'll format this PICC.");
                const auto rkey = km.keys().derive_token_root_key(*r_deployed);
                TRY(desfire::fs::login_app(token.tag(), desfire::root_app, rkey))
                TRY(token.tag().format_picc())
                TRY(desfire::fs::login_app(token.tag(), desfire::root_app, rkey))
                TRY(token.tag().change_key(desfire::key<desfire::cipher_type::des>{}))
            }
        } else if (ka::member_token::has_custom_meaning(r_deployed.error())) {
            ESP_LOGI(LOG_PFX, "Token deploy status: %s", ka::member_token::describe(r_deployed.error()));
            ESP_LOGI(LOG_PFX, "Attempting deploy.");
            TRY(token.deploy(km, unique_id))
        } else {
            return r_deployed.error();
        }
        return mlab::result_success;
    }

    pn532::post_interaction interact_with_token(ka::member_token &token) override {
        const bool success = bool(interact_with_token_internal(token));
        ESP_LOG_LEVEL_LOCAL((success ? ESP_LOG_INFO : ESP_LOG_ERROR), LOG_PFX, "Interaction complete.");
        return pn532::post_interaction::reject;
    }
};

void gate_main(pn532::controller &controller, pn532::scanner &scanner) {
    ESP_LOGI(LOG_PFX, "Reconfiguring as a new demo gate.");
    ka::gate gate;

    if (not gate.is_configured()) {
        ESP_LOGW(LOG_PFX, "Gate is not configured, entering target mode.");
        ka::p2p::configure_gate_loop(controller, gate);
        gate.config_store();
        ESP_LOGI(LOG_PFX, "Gate configured.");
    }

    gate.log_public_gate_info();

    ka::gate_responder responder{gate};
    scanner.loop(responder, false /* already performed */);
}

void keymaker_main(pn532::scanner &scanner) {
    keymaker_responder responder{};
    scanner.loop(responder, false /* already performed */);
}

void format_mcformatface_main(pn532::scanner &scanner) {
    format_mcformatface responder{};
    scanner.loop(responder, false /* already performed */);
}

extern "C" void app_main() {
    // In case someone forgets to disable logging root keys...
    desfire::esp32::suppress_log suppress{"AUTH ROOT KEY"};

    ESP_LOGI(LOG_PFX, "Waiting 2s to ensure the serial is attached and visible...");
    std::this_thread::sleep_for(2s);

    // Create WiFi
    std::shared_ptr<ka::wifi> wf = std::make_shared<ka::wifi>();

    // Create pn532, scanner and controller
    pn532::esp32::hsu_channel hsu_chn{ka::pinout::uart_port, ka::pinout::uart_config, ka::pinout::pn532_hsu_tx, ka::pinout::pn532_hsu_rx};
    pn532::controller controller{hsu_chn};
    pn532::scanner scanner{controller};

    // Do initial setup of the PN532
    if (not scanner.init_and_test_controller()) {
        // Is this a new fw? Roll back
        if (ka::firmware_version::is_running_fw_pending_verification()) {
            ESP_LOGE(LOG_PFX, "Could not start the PN532 with the new firmware. Will roll back in 5s.");
            std::this_thread::sleep_for(5s);
            ka::firmware_version::running_fw_rollback();
        }
        ESP_LOGE(LOG_PFX, "Power cycle the device to try again.");
        return;
    }

    ESP_LOGI(LOG_PFX, "Self-test passed.");

    // Is this a new fw? Mark as viable
    if (ka::firmware_version::is_running_fw_pending_verification()) {
        ka::firmware_version::running_fw_mark_verified();
        const auto v = ka::firmware_version::get_current();
        const auto v_s = v.to_string();
        ESP_LOGI(LOG_PFX, "Updated to version %s.", v_s.c_str());
    }

    // Now we are ready to set up the automated updates.
    /// @todo Increase to 1h or so
    ka::update_watch ota{wf, 5min};
    ota.start();

    // Enter main.
    int choice = 0;
    while (choice == 0) {
        std::printf("Select operation mode of the demo:\n");
        std::printf("\t1. Gate\n");
        std::printf("\t2. Keymaker\n");
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
            gate_main(controller, scanner);
            break;
        case 2:
            std::printf("Acting as keymaker.\n");
            keymaker_main(scanner);
            break;
        case 3:
            std::printf("Enter... Format McFormatface\n");
            format_mcformatface_main(scanner);
            break;
        default:
            break;
    }
    vTaskSuspend(nullptr);
}
