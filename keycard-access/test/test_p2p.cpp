//
// Created by spak on 7/6/23.
//

#include "test_p2p.hpp"
#include "test_bundle.hpp"
#include <chrono>
#include <desfire/esp32/utils.hpp>
#include <ka/keymaker.hpp>
#include <ka/p2p_ops.hpp>
#include <ka/secure_p2p.hpp>
#include <pn532/p2p.hpp>
#include <unity.h>

using namespace std::chrono_literals;

namespace ut {

    namespace {
        using ms = std::chrono::milliseconds;

        struct p2p_loopback : public pn532::p2p::initiator, public pn532::p2p::target {
            mlab::bin_data i2t_data, t2i_data;
            std::binary_semaphore i2t_avail{0}, t2i_avail{0};

            pn532::result<mlab::bin_data> receive(ms timeout) override {
                if (not i2t_avail.try_acquire_for(timeout)) {
                    return pn532::channel_error::timeout;
                }
                return i2t_data;
            }

            pn532::result<> send(mlab::bin_data const &data_to_send, ms timeout) override {
                t2i_data = data_to_send;
                t2i_avail.release();
                return mlab::result_success;
            }

            pn532::result<mlab::bin_data> communicate(mlab::bin_data const &data_to_send, ms timeout) override {
                i2t_data = data_to_send;
                i2t_avail.release();
                if (not t2i_avail.try_acquire_for(timeout)) {
                    return pn532::channel_error::timeout;
                }
                return t2i_data;
            }
        };

        struct secure_p2p_loopback : p2p_loopback {
            ka::p2p::secure_initiator initiator;
            ka::p2p::secure_target target;

            secure_p2p_loopback(ka::key_pair const &km_keys, ka::key_pair const &g_keys)
                : p2p_loopback{},
                  initiator{*this, g_keys},
                  target{*this, km_keys} {
                std::thread t{[&]() {
                    TEST_ASSERT(initiator.handshake(5s));
                }};
                TEST_ASSERT(target.handshake(5s));
                t.join();
            }
        };

        struct assertive_local_gate : public ka::p2p::v0::local_gate {
            using local_gate::local_gate;

            ka::p2p::r<ka::p2p::v0::update_settings> get_update_settings() override {
                return ka::p2p::v0::update_settings{"Foo bar", false};
            }

            ka::p2p::r<> set_update_settings(std::string_view update_channel, bool automatic_updates) override {
                TEST_ASSERT(update_channel == "The Channel");
                TEST_ASSERT(automatic_updates);
                return mlab::result_success;
            }

            ka::p2p::r<ka::p2p::v0::wifi_status> get_wifi_status() override {
                return ka::p2p::v0::wifi_status{"Nope", false};
            }

            ka::p2p::r<bool> connect_wifi(std::string_view ssid, std::string_view password) override {
                TEST_ASSERT(ssid == "Test SSID");
                TEST_ASSERT(password == "Test Password");
                return false;
            }

            ka::p2p::r<ka::p2p::v0::registration_info> get_registration_info() override {
                return ka::p2p::v0::registration_info{ka::gate_id{32}, g().keys().drop_secret_key()};
            }

            ka::p2p::r<ka::gate_base_key> register_gate(ka::gate_id requested_id) override {
                TEST_ASSERT(requested_id == ka::gate_id{13});
                return bundle.g0_bk;
            }

            ka::p2p::r<> reset_gate() override {
                return ka::p2p::error::unauthorized;
            }
        };


    }// namespace

    void test_p2p_comm() {
        ka::gate g{bundle.g0.keys()};
        ka::keymaker km{bundle.km_kp};
        secure_p2p_loopback loop{km.keys(), g.keys()};
        assertive_local_gate lg{loop.initiator, g};
        ka::p2p::v0::remote_gate rg{loop.target};

        TEST_ASSERT(loop.initiator.did_handshake());
        TEST_ASSERT(loop.target.did_handshake());

        std::thread t{[&]() { lg.serve_loop(); }};

        {
            ESP_LOGI("UT", "Testing %s", "hello");
            auto r = rg.hello();
            TEST_ASSERT(r);
        }
        {
            ESP_LOGI("UT", "Testing %s", "get_update_settings");
            auto r = rg.get_update_settings();
            TEST_ASSERT(r);
            if (r) {
                TEST_ASSERT(not r->enable_automatic_update);
                TEST_ASSERT(r->update_channel == "Foo bar");
            }
        }
        {
            ESP_LOGI("UT", "Testing %s", "set_update_settings");
            auto r = rg.set_update_settings("The Channel", true);
            TEST_ASSERT(r);
        }
        {
            ESP_LOGI("UT", "Testing %s", "get_wifi_status");
            auto r = rg.get_wifi_status();
            TEST_ASSERT(r);
            if (r) {
                TEST_ASSERT(r->ssid == "Nope");
                TEST_ASSERT(not r->operational);
            }
        }
        {
            ESP_LOGI("UT", "Testing %s", "connect_wifi");
            auto r = rg.connect_wifi("Test SSID", "Test Password");
            TEST_ASSERT(r);
            if (r) {
                TEST_ASSERT(not *r);
            }
        }
        {
            ESP_LOGI("UT", "Testing %s", "get_registration_info");
            auto r = rg.get_registration_info();
            TEST_ASSERT(r);
            if (r) {
                TEST_ASSERT(r->id == ka::gate_id{32});
                TEST_ASSERT(r->km_pk == g.keys());
            }
        }
        {
            ESP_LOGI("UT", "Testing %s", "register_gate");
            auto r = rg.register_gate(ka::gate_id{13});
            TEST_ASSERT(r);
            if (r) {
                TEST_ASSERT(*r == bundle.g0_bk);
            }
        }
        {
            ESP_LOGI("UT", "Testing %s", "reset_gate (unauthorized)");
            auto r = rg.reset_gate();
            TEST_ASSERT(not r);
            if (not r) {
                TEST_ASSERT(r.error() == ka::p2p::error::unauthorized);
            }
        }
        rg.bye();

        t.join();
    }

    void test_p2p_registration() {
        desfire::esp32::suppress_log suppress{ESP_LOG_ERROR, {"GATE", "P2P"}};

        ka::keymaker km1{bundle.km_kp};
        ka::keymaker km2{ka::key_pair{ka::pwhash, "foobar"}};
        ka::gate g{bundle.g0.keys()};

        secure_p2p_loopback loop1{km1.keys(), g.keys()};
        secure_p2p_loopback loop2{km2.keys(), g.keys()};

        ka::p2p::v0::remote_gate rg1{loop1.target};
        ka::p2p::v0::local_gate lg1{loop1.initiator, g};

        ka::p2p::v0::remote_gate rg2{loop2.target};
        ka::p2p::v0::local_gate lg2{loop2.initiator, g};

        std::thread t1{[&]() { lg1.serve_loop(); }};
        std::thread t2{[&]() { lg2.serve_loop(); }};

        auto is_unauthorized = [](auto const &r) { return not r and r.error() == ka::p2p::error::unauthorized; };
        auto is_invalid = [](auto const &r) { return not r and r.error() == ka::p2p::error::invalid; };

        // Do the setup with km1
        TEST_ASSERT(rg1.hello());
        TEST_ASSERT(rg1.register_gate(ka::gate_id{11}));
        TEST_ASSERT(is_invalid(rg1.register_gate(ka::gate_id{11})));

        // Attempt to register with km2
        TEST_ASSERT(rg2.hello());
        TEST_ASSERT(is_invalid(rg2.register_gate(ka::gate_id{12})));
        TEST_ASSERT(is_unauthorized(rg2.reset_gate()));
        TEST_ASSERT(is_unauthorized(rg2.connect_wifi("foo", "bar")));
        TEST_ASSERT(is_unauthorized(rg2.set_update_settings("foo", false)));

        // Reset with km1
        TEST_ASSERT(rg1.reset_gate());
        TEST_ASSERT(rg2.register_gate(ka::gate_id{11}));

        // Good.
        rg1.bye();
        rg2.bye();

        t1.join();
        t2.join();
    }
}// namespace ut