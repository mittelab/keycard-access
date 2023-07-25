#include <chrono>
#include <desfire/esp32/utils.hpp>
#include <ka/config.hpp>
#include <ka/console.hpp>
#include <ka/gpio_auth_responder.hpp>
#include <ka/keymaker.hpp>
#include <ka/nvs.hpp>
#include <mlab/result_macro.hpp>
#include <pn532/esp32/hsu.hpp>
#include <thread>

// Override the log prefix
#define TAG "KA"

using namespace std::chrono_literals;

namespace {
    void fw_rollback(const char *what_went_wrong) {
        if (ka::fw_info::is_running_fw_pending_verification()) {
            ESP_LOGE(TAG, "Could not %s with the new firmware. Will roll back in 5s.", what_went_wrong);
            std::this_thread::sleep_for(5s);
            ka::fw_info::running_fw_rollback();
        }
    }

    void fw_is_good() {
        if (ka::fw_info::is_running_fw_pending_verification()) {
            ESP_LOGI(TAG, "Firmware was updated.");
            ka::fw_info::running_fw_mark_verified();
        }
    }
}

void keymaker_main(ka::nvs::partition &partition, std::shared_ptr<pn532::controller> ctrl) {
    // Generate a fresh new keypair, which we will then override if any is found
    ka::key_pair kp{ka::randomize};
    ka::device_keypair_storage kp_storage{partition};

    ESP_LOGI(TAG, "Waiting 2s to ensure the serial is attached and visible...");
    std::this_thread::sleep_for(2s);

    ka::console console;

    if (kp_storage.exists()) {
        // Ask the password to unlock it
        auto pw = kp_storage.prompt_for_password(console, false);
        assert(pw);
        auto opt_kp = kp_storage.load(*pw);
        assert(opt_kp);
        kp = *opt_kp;
    } else {
        // This is the first run, ask the user for a password
        auto pw = ka::device_keypair_storage::prompt_for_new_password(console, false, false);
        assert(pw);
        // Save the new key pair using the password
        kp_storage.save(kp, *pw);
    }

    ka::keymaker km{partition, std::move(kp_storage), kp, std::move(ctrl)};
    ka::cmd::shell sh;
    sh.register_help_command();
    km.register_commands(sh);

    // This is the latest point at which we have done something and can certify to a good
    // extent the firmware is working (no broken key pair, no broken storage, rf field working...)
    fw_is_good();

    ESP_LOGI(TAG, "Entering shell, type 'help' for help:");

    sh.repl(console);

    ESP_LOGI(TAG, "Exiting shell.");
}

[[noreturn]] void gate_main(ka::nvs::partition &partition, std::shared_ptr<pn532::controller> const &ctrl) {
    ka::gate g{partition};
    if (g.is_configured()) {
        ESP_LOGI(TAG, "Gate configured as gate %lu with keymaker public key:", std::uint32_t{g.id()});
        ESP_LOG_BUFFER_HEX_LEVEL(TAG, g.keymaker_pk().raw_pk().data(), g.keymaker_pk().raw_pk().size(), ESP_LOG_INFO);
    } else {
        ESP_LOGI(TAG, "Gate not configured.");
    }

    // Make sure GPIO configuration is loaded now, not at the first usage
    static_cast<void>(ka::gpio_responder_config::get_global_config());
    ka::gpio_gate_responder responder{g};
    pn532::scanner scanner{*ctrl};

    // This is the latest point at which we have done something and can certify to a good
    // extent the firmware is working (no broken key pair, no broken storage, rf field working...)
    fw_is_good();

    while (true) {
        scanner.loop(responder, false);
    }
}

extern "C" void app_main() {
    std::printf("\nKeycard Access  Copyright (C) 2023  Pietro Saccardi\n\n"
                "This program comes with ABSOLUTELY NO WARRANTY.\n"
                "This is free software, and you are welcome to\n"
                "redistribute it under certain conditions.\n"
                "See the LICENSE file in the source code for details.\n\n");
    auto fw_str = ka::fw_info::get_running_fw().to_string();
    std::printf("Firmware version: %s\n\n", fw_str.c_str());

    // Open the main partition and ensure it works correctly.
    auto partition = ka::nvs::instance().open_default_partition();
    if (partition == nullptr) {
        // This is severe, we cannot do anything without NVS partition.
        fw_rollback("open the NVS partition");
        ESP_LOGE(TAG, "Could not %s, power cycle the device to try again.", "open the NVS partition");
        return;
    }

    // In case someone forgets to disable logging root keys...
    desfire::esp32::suppress_log suppress{"AUTH ROOT KEY"};

    // Create pn532, scanner and controller
    pn532::esp32::hsu_channel hsu_chn{ka::pinout::uart_port, ka::pinout::uart_config, ka::pinout::pn532_hsu_tx, ka::pinout::pn532_hsu_rx};
    auto controller = std::make_shared<pn532::controller>(hsu_chn);

    // Do initial setup of the PN532
    if (not hsu_chn.wake() or not controller->init_and_test()) {
        // Is this a new fw? Roll back
        fw_rollback("start the PN532");
        ESP_LOGE(TAG, "Could not %s, power cycle the device to try again.", "start the PN532");
        return;
    }

#if defined(KEYCARD_ACCESS_GATE)
    gate_main(*partition, controller);
#else
    keymaker_main(*partition, controller);
#endif
    vTaskSuspend(nullptr);
}
