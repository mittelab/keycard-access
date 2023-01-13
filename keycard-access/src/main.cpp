#include <freertos/FreeRTOS.h>
#include <freertos/task.h>
#include <ka/member_token.hpp>
#include <esp_log.h>
#include <ka/config.hpp>
#include <ka/nvs.hpp>
#include <pn532/controller.hpp>
#include <pn532/esp32/hsu.hpp>

using namespace std::chrono_literals;

extern "C" void app_main() {
    ESP_LOGI("KA", "Loading configuration.");
    auto g = ka::gate::load_or_generate();
    ESP_LOGI("KA", "Device public key:");
    ESP_LOG_BUFFER_HEX_LEVEL("KA", g.keys().raw_pk().data(), ka::raw_pub_key::array_size, ESP_LOG_INFO);
    if (not g.is_configured()) {
        ESP_LOGW("KA", "Device is not configured.");
    } else {
        ESP_LOGI("KA", "Gate %d \"%s\".", g.id(), g.description().c_str());
        ESP_LOGI("KA", "Registered to programmer's public key:");
        ESP_LOG_BUFFER_HEX_LEVEL("KA", g.programmer_pub_key().raw_pk().data(), ka::raw_pub_key::array_size, ESP_LOG_INFO);
    }

    pn532::esp32::hsu_channel hsu_chn{ka::pinout::uart_port, ka::pinout::uart_config, ka::pinout::pn532_hsu_tx, ka::pinout::pn532_hsu_rx};
    pn532::controller controller{hsu_chn};

    if (not hsu_chn.wake() or not controller.sam_configuration(pn532::sam_mode::normal, 1s)) {
        ESP_LOGE("KA", "Unable to connect to PN532.");
    } else {
        ESP_LOGI("KA", "Performing self-test of the PN532.");
        if (not controller.diagnose_comm_line()) {
            ESP_LOGE("KA", "Failed comm line diagnostics.");
        } else if (not controller.diagnose_self_antenna(pn532::low_current_thr::mA_25, pn532::high_current_thr::mA_150)) {
            ESP_LOGE("KA", "Failed antenna diagnostics.");
        } else {
            ESP_LOGI("KA", "PN532 passed all tests.");
            if (g.is_configured()) {
                g.loop(controller);
            }
        }
    }

    vTaskSuspend(nullptr);
}
