#include <esp_log.h>
#include <freertos/FreeRTOS.h>
#include <freertos/task.h>
#include <ka/config.hpp>
#include <ka/gate.hpp>
#include <ka/p2p_ops.hpp>
#include <pn532/controller.hpp>
#include <pn532/esp32/hsu.hpp>

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
        ka::p2p::configure_gate(controller, gate);
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

extern "C" void app_main() {
    gate_main();
    vTaskSuspend(nullptr);
}
