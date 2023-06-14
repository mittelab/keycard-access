//
// Created by spak on 1/20/23.
//

#ifndef KEYCARD_ACCESS_P2P_OPS_HPP
#define KEYCARD_ACCESS_P2P_OPS_HPP

#include <ka/gate.hpp>
#include <ka/key_pair.hpp>
#include <pn532/p2p.hpp>

namespace ka {
    class gate;
    class secure_target;
    class secure_initiator;
}// namespace ka
namespace ka::p2p {

    pn532::result<> configure_gate_exchange(keymaker &km, secure_initiator &comm, std::string const &gate_description);
    pn532::result<> configure_gate_exchange(gate &g, secure_target &comm);

    [[nodiscard]] bool configure_gate_in_rf(pn532::controller &ctrl, gate &g);
    [[nodiscard]] bool configure_gate_in_rf(pn532::controller &ctrl, std::uint8_t logical_index, keymaker &km, std::string const &gate_description);

    void configure_gate_loop(pn532::controller &ctrl, gate &g);
    [[nodiscard]] bool configure_gate_loop(pn532::controller &ctrl, keymaker &km, std::string const &gate_description);

}// namespace ka::p2p

#endif//KEYCARD_ACCESS_P2P_OPS_HPP
