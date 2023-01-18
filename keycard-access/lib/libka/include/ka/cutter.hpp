//
// Created by Aljaž Srebrnič on 18/01/23.
//

#ifndef KEYCARDACCESS_CUTTER_HPP
#define KEYCARDACCESS_CUTTER_HPP

#include <pn532/controller.hpp>

namespace ka {
    class cutter {
        static constexpr auto publisher = "www.mittelab.org";

        identity select_identity();
        gate select_gate();

        member_token find_card(pn532::controller &controller);

        void cut_key(pn532::controller &controller, identity id);
        void configure_key_for_gate(pn532::controller &controller, gate g);
    public:
        [[noreturn]] void loop(pn532::controller&& controller);
    };
}// namespace ka

#endif//KEYCARDACCESS_CUTTER_HPP
