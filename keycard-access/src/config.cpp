//
// Created by spak on 10/2/22.
//

#include "config.hpp"

namespace ka {
    namespace {
        [[nodiscard]] config &the_config() {
            static config _cfg;
            return _cfg;
        }
    }

    config const &system_config() {
        return the_config();
    }
}