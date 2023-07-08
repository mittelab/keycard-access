//
// Created by spak on 6/13/23.
//

#include "gate_main.hpp"
#include <esp_log.h>
#include <ka/gate.hpp>
#include <ka/p2p_ops.hpp>

#define LOG_PFX "KA-GATE"

namespace ka {
    void gate_main(pn532::scanner &scanner) {
        ESP_LOGI(LOG_PFX, "Reconfiguring as a new demo gate.");
        ka::gate gate{nvs::instance().open_default_partition()};
        ka::gate_responder responder{gate};
        scanner.loop(responder, false /* already performed */);
    }
}// namespace ka
