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

void keymaker_main(std::shared_ptr<pn532::controller> ctrl) {
    ESP_LOGI(TAG, "Waiting 2s to ensure the serial is attached and visible...");
    std::this_thread::sleep_for(2s);

    ka::console console;

    std::optional<std::string> password;
    do {
        std::printf("Please enter the password to unlock this keymaker:\n");
        password = console.read_line();
    } while (password == std::nullopt);

    ka::keymaker km{ka::nvs::instance().open_default_partition(), std::move(ctrl), std::move(*password)};
    ka::cmd::shell sh;
    sh.register_help_command();
    km.register_commands(sh);

    ESP_LOGI(TAG, "Entering shell, type 'help' for help:");

    sh.repl(console);

    ESP_LOGI(TAG, "Exiting shell.");
}

[[noreturn]] void gate_main(std::shared_ptr<pn532::controller> const &ctrl) {
    ka::gate g{ka::nvs::instance().open_default_partition()};
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
    if (not hsu_chn.wake() or not controller->init_and_test()) {
        // Is this a new fw? Roll back
        if (ka::fw_info::is_running_fw_pending_verification()) {
            ESP_LOGE(TAG, "Could not start the PN532 with the new firmware. Will roll back in 5s.");
            std::this_thread::sleep_for(5s);
            ka::fw_info::running_fw_rollback();
        }
        ESP_LOGE(TAG, "Power cycle the device to try again.");
        return;
    }

    ESP_LOGI(TAG, "Self-test passed.");

#if defined(KEYCARD_ACCESS_GATE)
    gate_main(controller);
#else
    keymaker_main(controller);
#endif
    vTaskSuspend(nullptr);
}
