#include <ka/member_token.hpp>
#include <desfire/esp32/cipher_provider.hpp>
#include <esp_log.h>
#include <freertos/FreeRTOS.h>
#include <freertos/task.h>
#include <ka/config.hpp>
#include <ka/nvs.hpp>
#include <pn532/controller.hpp>
#include <pn532/desfire_pcd.hpp>
#include <pn532/esp32/hsu.hpp>


using namespace std::chrono_literals;

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

void interact_with_token(ka::gate_config const &cfg, ka::member_token &token) {
    ESP_LOGW("KA", "Not implemented yet");
}

[[noreturn]] void gate_loop(ka::gate_config const &cfg, pn532::controller &controller) {
    using cipher_provider = desfire::esp32::default_cipher_provider;
    while (true) {
        const auto r = controller.initiator_list_passive_kbps106_typea(1);
        if (not r or r->empty()) {
            continue;
        }
        // A card was scanned!
        ESP_LOGI("KA", "Found passive target with NFC ID:");
        ESP_LOG_BUFFER_HEX_LEVEL("KA", r->front().info.nfcid.data(), r->front().info.nfcid.size(), ESP_LOG_INFO);
        auto tag = desfire::tag::make<cipher_provider>(pn532::desfire_pcd{controller, r->front().logical_index});
        ka::member_token token{tag};
        interact_with_token(cfg, token);
    }
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
            if (cfg.is_configured()) {
                gate_loop(cfg, controller);
            }
        }
    }

    vTaskSuspend(nullptr);
}
