//
// Created by spak on 21/05/24.
//
#include <catch/catch.hpp>

extern "C" int app_main() {
    Catch::Session session;
    session.configData().name = "KeycardAccess";
    session.configData().runOrder = Catch::TestRunOrder::LexicographicallySorted;
    session.configData().verbosity = Catch::Verbosity::Quiet;
    session.configData().noThrow = true;
    return session.run();
}