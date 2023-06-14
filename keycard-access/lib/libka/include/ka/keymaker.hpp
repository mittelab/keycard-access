//
// Created by spak on 6/14/23.
//

#ifndef KEYCARD_ACCESS_KEYMAKER_HPP
#define KEYCARD_ACCESS_KEYMAKER_HPP

#include <ka/gate.hpp>
#include <ka/key_pair.hpp>

namespace ka {

    class keymaker {
    public:
        key_pair _kp{randomize};
        std::vector<gate_config> _gates;

        [[nodiscard]] key_pair const &keys() const { return _kp; }
        [[nodiscard]] gate_id allocate_gate_id() { return gate_id{_gates.size()}; }
        void register_gate(gate_config cfg) {
            if (cfg.id == _gates.size()) {
                _gates.emplace_back(cfg);
            } else {
                ESP_LOGE("KA", "Invalid gate.");
            }
        }
    };

}// namespace ka

#endif//KEYCARD_ACCESS_KEYMAKER_HPP
