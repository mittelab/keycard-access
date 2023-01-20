//
// Created by spak on 1/20/23.
//

#ifndef KEYCARD_ACCESS_P2P_OPS_HPP
#define KEYCARD_ACCESS_P2P_OPS_HPP

#include <pn532/p2p.hpp>

namespace ka {
    class gate;
}
namespace ka::p2p {

    void configure_gate(pn532::controller &ctrl, gate &g);
}

#endif//KEYCARD_ACCESS_P2P_OPS_HPP
