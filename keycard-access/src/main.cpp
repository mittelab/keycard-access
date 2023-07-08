#include <chrono>
#include <desfire/esp32/utils.hpp>
#include <ka/console.hpp>
#include <ka/keymaker.hpp>
#include <ka/nvs.hpp>
#include <thread>
#include <ka/config.hpp>
#include <pn532/esp32/hsu.hpp>

// Override the log prefix
#define LOG_PFX "KA"

using namespace std::chrono_literals;

void keymaker_main(std::shared_ptr<pn532::controller> ctrl) {
    ka::keymaker km{ka::nvs::instance().open_default_partition(), std::move(ctrl)};

    ESP_LOGI(LOG_PFX, "Waiting 2s to ensure the serial is attached and visible...");
    std::this_thread::sleep_for(2s);

    ka::console console;
    ka::cmd::shell sh;
    sh.register_help_command();
    km.register_commands(sh);

    ESP_LOGI(LOG_PFX, "Entering shell, type 'help' for help:");

    sh.repl(console);

    ESP_LOGI(LOG_PFX, "Exiting shell.");
}

[[noreturn]] void gate_main(std::shared_ptr<pn532::controller> const &ctrl) {
    ka::gate g{ka::nvs::instance().open_default_partition()};
    ka::gate_responder responder{g};
    pn532::scanner scanner{*ctrl};
    while (true) {
        scanner.loop(responder, false);
    }
}

extern "C" void app_main() {
    // In case someone forgets to disable logging root keys...
    desfire::esp32::suppress_log suppress{"AUTH ROOT KEY"};

    // Create pn532, scanner and controller
    pn532::esp32::hsu_channel hsu_chn{ka::pinout::uart_port, ka::pinout::uart_config, ka::pinout::pn532_hsu_tx, ka::pinout::pn532_hsu_rx};
    auto controller = std::make_shared<pn532::controller>(hsu_chn);

    // Do initial setup of the PN532
    if (not controller->init_and_test()) {
        // Is this a new fw? Roll back
        if (ka::fw_info::is_running_fw_pending_verification()) {
            ESP_LOGE(LOG_PFX, "Could not start the PN532 with the new firmware. Will roll back in 5s.");
            std::this_thread::sleep_for(5s);
            ka::fw_info::running_fw_rollback();
        }
        ESP_LOGE(LOG_PFX, "Power cycle the device to try again.");
        return;
    }

    ESP_LOGI(LOG_PFX, "Self-test passed.");

#if defined(KEYCARD_ACCESS_GATE)
    gate_main(controller);
#else
    keymaker_main(controller);
#endif
    vTaskSuspend(nullptr);
}
