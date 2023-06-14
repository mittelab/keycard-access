//
// Created by spak on 6/13/23.
//

#ifndef KEYCARD_ACCESS_KEYMAKER_MAIN_HPP
#define KEYCARD_ACCESS_KEYMAKER_MAIN_HPP

namespace pn532 {
    class scanner;
}

namespace ka {
    void keymaker_main(pn532::scanner &scanner);
}

#endif//KEYCARD_ACCESS_KEYMAKER_MAIN_HPP
