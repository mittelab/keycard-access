//
// Created by spak on 1/20/23.
//

#ifndef KEYCARD_ACCESS_P2P_OPS_HPP
#define KEYCARD_ACCESS_P2P_OPS_HPP

#include <pn532/p2p.hpp>

namespace ka {
    class gate;

    struct keymaker_mock {
        key_pair _kp{randomize};

        [[nodiscard]] key_pair const &keys() const { return _kp; }
        [[nodiscard]] gate_id allocate_gate_id() { return 0xf00ba2; }
        void register_gate([[maybe_unused]] gate_id gid, [[maybe_unused]] raw_pub_key gate_pk, [[maybe_unused]] std::string const &description) {}
    };

    using keymaker = keymaker_mock;
}
namespace ka::p2p {

    void configure_gate(pn532::controller &ctrl, gate &g);
    [[nodiscard]] bool configure_gate(pn532::controller &ctrl, keymaker &km, std::string gate_description);
}

#endif//KEYCARD_ACCESS_P2P_OPS_HPP
