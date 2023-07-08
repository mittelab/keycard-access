//
// Created by spak on 6/13/23.
//

#ifndef KEYCARD_ACCESS_GATE_MAIN_HPP
#define KEYCARD_ACCESS_GATE_MAIN_HPP

namespace pn532 {
    class controller;
    class scanner;

}// namespace pn532
namespace ka {
    void gate_main(pn532::scanner &scanner);
}

#endif//KEYCARD_ACCESS_GATE_MAIN_HPP
