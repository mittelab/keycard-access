#include "formatter_main.hpp"
#include "gate_main.hpp"
#include "keymaker_main.hpp"
#include <chrono>
#include <desfire/esp32/utils.hpp>
#include <esp_console.h>
#include <esp_log.h>
#include <ka/config.hpp>
#include <ka/console.hpp>
#include <ka/ota.hpp>
#include <ka/wifi.hpp>
#include <memory>
#include <pn532/controller.hpp>
#include <pn532/esp32/hsu.hpp>
#include <pn532/scanner.hpp>
#include <thread>

// Override the log prefix
#define LOG_PFX "KA"

using namespace std::chrono_literals;


extern "C" void app_main() {
    // In case someone forgets to disable logging root keys...
    desfire::esp32::suppress_log suppress{"AUTH ROOT KEY"};

    ESP_LOGI(LOG_PFX, "Waiting 2s to ensure the serial is attached and visible...");
    std::this_thread::sleep_for(2s);

    // Create WiFi
    auto &wf = ka::wifi::instance();

    // Create pn532, scanner and controller
    pn532::esp32::hsu_channel hsu_chn{ka::pinout::uart_port, ka::pinout::uart_config, ka::pinout::pn532_hsu_tx, ka::pinout::pn532_hsu_rx};
    pn532::controller controller{hsu_chn};
    pn532::scanner scanner{controller};

    // Do initial setup of the PN532
    if (not scanner.init_and_test_controller()) {
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

    // Is this a new fw? Mark as viable
    if (const auto v = ka::fw_info::get_running_fw(); ka::fw_info::is_running_fw_pending_verification()) {
        ka::fw_info::running_fw_mark_verified();
        const auto v_s = v.to_string();
        ESP_LOGI(LOG_PFX, "Updated to version %s.", v_s.c_str());
    } else {
        const auto v_s = v.to_string();
        ESP_LOGI(LOG_PFX, "Running version %s.", v_s.c_str());
    }

    // Now we are ready to set up the automated updates.
    ka::ota_watch ota{1h};
    ota.start();

    ka::console console;

    // Enter main.
    while (true) {
        std::printf("Select operation mode of the demo:\n");
        std::printf("\t1. Gate\n");
        std::printf("\t2. Keymaker\n");
        std::printf("\t3. FormatMcFormatface\n");
        const auto choice = console.read_line();
        if (choice == "1" or choice == "gate") {
            std::printf("Acting as gate.\n");
            ka::gate_main(controller, scanner);
        } else if (choice == "2" or choice == "keymaker") {
            std::printf("Acting as keymaker.\n");
            ka::keymaker_main(scanner);
        } else if (choice == "3" or choice == "format") {
            std::printf("Enter... Format McFormatface\n");
            ka::format_mcformatface_main(scanner);
        } else {
            std::printf("Please insert 1, 2 or 3.\n");
            continue;
        }
        break;
    }
    vTaskSuspend(nullptr);
}
