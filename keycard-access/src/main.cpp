#include <chrono>
#include <desfire/esp32/utils.hpp>
#include <ka/console.hpp>
#include <ka/device.hpp>
#include <thread>

// Override the log prefix
#define LOG_PFX "KA"

using namespace std::chrono_literals;


extern "C" void app_main() {
    // In case someone forgets to disable logging root keys...
    desfire::esp32::suppress_log suppress{"AUTH ROOT KEY"};

    ka::device this_device;

    ESP_LOGI(LOG_PFX, "Waiting 2s to ensure the serial is attached and visible...");
    std::this_thread::sleep_for(2s);

    ka::console console;
    ka::cmd::shell sh;
    sh.register_help_command();
    this_device.register_commands(sh);

    ESP_LOGI(LOG_PFX, "Entering shell, type 'help' for help:");

    sh.repl(console);

    ESP_LOGI(LOG_PFX, "Exiting shell.");

    vTaskSuspend(nullptr);
}
