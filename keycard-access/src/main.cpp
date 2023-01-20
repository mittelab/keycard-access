#include <desfire/tag_responder.hpp>
#include <esp_log.h>
#include <freertos/FreeRTOS.h>
#include <freertos/task.h>
#include <ka/config.hpp>
#include <ka/gate.hpp>
#include <ka/nvs.hpp>
#include <ka/secure_p2p.hpp>
#include <pn532/controller.hpp>
#include <pn532/esp32/hsu.hpp>
#include <thread>

using namespace std::chrono_literals;

void target_loop(pn532::controller &controller) {
    ka::key_pair kp{ka::randomize};
    ka::nfc::pn532_target raw_comm{controller};
    ESP_LOGI("TARGET", "Activating...");
    if (const auto r = raw_comm.init_as_dep_target({}); r) {
        ESP_LOGI("TARGET", "Activated. PICC: %d, DEP: %d, %s", r->mode.iso_iec_14443_4_picc, r->mode.dep, pn532::to_string(r->mode.speed));
    } else {
        ESP_LOGW("TARGET", "Failed activation.");
        return;
    }
    ka::nfc::secure_target comm{raw_comm, kp};
    for (auto r = comm.receive(1s); r; r = comm.receive(1s)) {
        const std::string cmd = mlab::data_to_string(*r);
        ESP_LOGI("TARGET", "Received: %s", cmd.c_str());
        if (cmd == "quit") {
            comm.send({}, 1s);
            break;
        }
        std::string response = "You typed: \"";
        response.append(cmd);
        response.append("\"");
        comm.send(mlab::data_from_string(response), 1s);
    }
    ESP_LOGI("TARGET", "Released.");
}

void initiator_loop(pn532::controller &controller) {
    ka::key_pair kp{ka::randomize};
    if (auto r = controller.initiator_auto_poll(); r) {
        for (std::size_t i = 0; i < r->size(); ++i) {
            if (r->at(i).type() == pn532::target_type::dep_passive_106kbps) {
                ESP_LOGI("PN532", "Detected DEP passive target, comm is on.");
                const auto log_idx = r->at(i).get<pn532::target_type::dep_passive_106kbps>().logical_index;
                ka::nfc::pn532_initiator raw_comm{controller, log_idx};
                ka::nfc::secure_initiator comm{raw_comm, kp};
                if (const auto r_comm = comm.communicate(mlab::data_from_string("test"), 1s); r_comm) {
                    const auto s = mlab::data_to_string(*r_comm);
                    ESP_LOGI(">>", "%s", s.c_str());
                }
                if (const auto r_comm = comm.communicate(mlab::data_from_string("toast"), 1s); r_comm) {
                    const auto s = mlab::data_to_string(*r_comm);
                    ESP_LOGI(">>", "%s", s.c_str());
                }
                if (const auto r_comm = comm.communicate(mlab::data_from_string("quit"), 1s); r_comm) {
                    const auto s = mlab::data_to_string(*r_comm);
                    ESP_LOGI(">>", "%s", s.c_str());
                }
                controller.initiator_release(i);
                break;
            }
            controller.initiator_release(i);
        }
    } else {
        ESP_LOGW("PN532", "Polling failed.");
    }
}

extern "C" void app_main() {
    ESP_LOGI("KA", "Loading configuration.");
    auto g = ka::gate::config_load_or_generate();
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
    pn532::scanner scanner{controller};
#if defined(KEYCARD_ACCESS_GATE)
    ka::gate_responder responder{g};
    scanner.loop(responder);
#else
    if (scanner.init_and_test_controller()) {
        while (true) {
#if defined(KEYCARD_ACCESS_TARGET)
            target_loop(controller);
#elif defined(KEYCARD_ACCESS_INITIATOR)
            initiator_loop(controller);
#endif
            std::this_thread::sleep_for(2s);
        }
    }
#endif
    vTaskSuspend(nullptr);
}
