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

extern "C" void app_main() {
    desfire::esp32::suppress_log suppress{"AUTH ROOT KEY"};
    ESP_LOGI("KA", "Waiting 2s to ensure the serial is attached and visible...");
    vTaskDelay(pdMS_TO_TICKS(2000));
    int choice = 0;
    while (choice == 0) {
        std::printf("Select operation mode of the demo:\n");
        std::printf("\t1. gate\n");
        std::printf("\t2. keymaker\n");
        std::printf("> ");
        while (std::scanf("%d", &choice) != 1) {
            vTaskDelay(pdMS_TO_TICKS(100));
        }
        if (choice != 1 and choice != 2) {
            std::printf("Insert '1' or '2'.");
            choice = 0;
        }
    }
    std::printf("\n");
    if (choice == 1) {
        std::printf("Acting as gate.\n");
        gate_main();
    } else {
        std::printf("Acting as keymaker.\n");
        keymaker_main();
    }
    vTaskSuspend(nullptr);
}
