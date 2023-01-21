//
// Created by spak on 1/20/23.
//

#ifndef KEYCARD_ACCESS_P2P_OPS_HPP
#define KEYCARD_ACCESS_P2P_OPS_HPP

#include <pn532/p2p.hpp>

namespace ka {
    class gate;
    class secure_target;
    class secure_initiator;

    struct keymaker_mock {
        key_pair _kp{randomize};

        [[nodiscard]] key_pair const &keys() const { return _kp; }
        [[nodiscard]] gate_id allocate_gate_id() { return 0xf00ba2; }
        void register_gate([[maybe_unused]] gate_id gid, [[maybe_unused]] raw_pub_key gate_pk, [[maybe_unused]] std::string description) {}
    };

    using keymaker = keymaker_mock;
}
namespace ka::p2p {

    pn532::p2p::result<> configure_gate_exchange(keymaker &km, secure_initiator &comm, std::string gate_description);
    pn532::p2p::result<> configure_gate_exchange(gate &g, secure_target &comm);

    [[nodiscard]] bool configure_gate_in_rf(pn532::controller &ctrl, gate &g);
    [[nodiscard]] bool configure_gate_in_rf(pn532::controller &ctrl, std::uint8_t logical_index, keymaker &km, std::string gate_description);

    void configure_gate_loop(pn532::controller &ctrl, gate &g);
    [[nodiscard]] bool configure_gate_loop(pn532::controller &ctrl, keymaker &km, std::string gate_description);

}

#endif//KEYCARD_ACCESS_P2P_OPS_HPP
