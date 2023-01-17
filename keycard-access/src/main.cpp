#include <freertos/FreeRTOS.h>
#include <freertos/task.h>
#include <ka/member_token.hpp>
#include <esp_log.h>
#include <ka/config.hpp>
#include <ka/nvs.hpp>
#include <pn532/controller.hpp>
#include <pn532/esp32/hsu.hpp>

using namespace std::chrono_literals;

struct log_responder final : public ka::gate_responder {
    void on_approach(ka::token_id const &id) override {
        ESP_LOGI("RESP", "on_approach");
    }
    void on_authentication_begin(ka::token_id const &id) override {
        ESP_LOGI("RESP", "on_authentication_begin");
    }
    void on_authentication_success(ka::identity const &id) override {
        ESP_LOGI("RESP", "on_authentication_success");
    }
    void on_authentication_fail(ka::token_id const &id, desfire::error auth_error, ka::r<ka::identity> const &unverified_id, bool might_be_tampering) override {
        ESP_LOGI("RESP", "on_authentication_fail");
    }
    void on_interaction_complete(ka::token_id const &id) override {
        ESP_LOGI("RESP", "on_interaction_complete");
    }
    void on_removal(ka::token_id const &id) override {
        ESP_LOGI("RESP", "on_removal");
    }
};

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
    log_responder responder{};

    if (not hsu_chn.wake() or not controller.sam_configuration(pn532::sam_mode::normal, 1s)) {
        ESP_LOGE("KA", "Unable to connect to PN532.");
    } else {
        ESP_LOGI("KA", "Performing self-test of the PN532.");
        if (const auto r_comm = controller.diagnose_comm_line(); not r_comm or not *r_comm) {
            ESP_LOGE("KA", "Failed comm line diagnostics.");
        } else {
            if (const auto r_antenna = controller.diagnose_self_antenna(pn532::low_current_thr::mA_25, pn532::high_current_thr::mA_150);
                not r_antenna or not *r_antenna) {
                ESP_LOGW("KA", "Failed antenna diagnostics.");
            } else {
                ESP_LOGI("KA", "PN532 passed all tests.");
            }
            if (g.is_configured()) {
                g.loop(controller, responder);
            }
        }
    }

    vTaskSuspend(nullptr);
}
