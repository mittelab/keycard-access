#include <esp_log.h>
#include <freertos/FreeRTOS.h>
#include <freertos/task.h>
#include <ka/config.hpp>
#include <ka/nvs.hpp>


void wait() {
    for (std::size_t i = 0; i < 5; ++i) {
        ESP_LOGI("KA", "Waiting %d/5", i);
        vTaskDelay(pdMS_TO_TICKS(1000));
    }
}

[[nodiscard]] ka::gate_config load_config() {
    ka::nvs::nvs nvs;
    auto partition = nvs.open_partition(NVS_DEFAULT_PART_NAME, false);
    if (partition == nullptr) {
        ESP_LOGE("KA", "NVS partition is not available.");
        return ka::gate_config::generate();
    }
    return ka::gate_config::load_from_nvs(*partition);
}

extern "C" void app_main() {
    wait();
    ESP_LOGI("KA", "Loading configuration.");
    const auto cfg = load_config();
    ESP_LOGI("KA", "Device public key:");
    ESP_LOG_BUFFER_HEX_LEVEL("KA", cfg.keys().raw_pk().data(), ka::raw_pub_key::key_size, ESP_LOG_INFO);
    if (not cfg.is_configured()) {
        ESP_LOGW("KA", "Device is not configured.");
    } else {
        ESP_LOGI("KA", "Gate %d \"%s\".", cfg.id(), cfg.description().c_str());
        ESP_LOGI("KA", "Registered to programmer's public key:");
        ESP_LOG_BUFFER_HEX_LEVEL("KA", cfg.programmer_pub_key().raw_pk().data(), ka::raw_pub_key::key_size, ESP_LOG_INFO);
    }
    vTaskSuspend(nullptr);
}
