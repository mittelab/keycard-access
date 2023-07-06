//
// Created by spak on 7/6/23.
//

#include "test_p2p.hpp"
#include <chrono>
#include <ka/keymaker.hpp>
#include <ka/p2p_ops.hpp>
#include <ka/secure_p2p.hpp>
#include <pn532/p2p.hpp>
#include <unity.h>

using namespace std::chrono_literals;

namespace ut {

    namespace {
        using ms = std::chrono::milliseconds;

        struct test_p2p : public pn532::p2p::initiator, public pn532::p2p::target {
            mlab::bin_data data{};
            std::condition_variable i2t_ready{};
            std::mutex i2t_ready_mutex{};
            std::condition_variable t2i_ready{};
            std::mutex t2i_ready_mutex{};

            pn532::result<mlab::bin_data> receive(ms timeout) override {
                std::unique_lock<std::mutex> lock{i2t_ready_mutex};
                if (i2t_ready.wait_for(lock, timeout) == std::cv_status::no_timeout) {
                    return data;
                }
                return pn532::channel_error::timeout;
            }

            pn532::result<> send(mlab::bin_data const &data_to_send, ms timeout) override {
                data = data_to_send;
                t2i_ready.notify_one();
                return mlab::result_success;
            }

            pn532::result<mlab::bin_data> communicate(mlab::bin_data const &data_to_send, ms timeout) override {
                std::unique_lock<std::mutex> lock{t2i_ready_mutex};
                data = data_to_send;
                i2t_ready.notify_one();
                if (t2i_ready.wait_for(lock, timeout) == std::cv_status::no_timeout) {
                    return data;
                }
                return pn532::channel_error::timeout;
            }
        };

        struct test_bundle {
            ka::keymaker km{
                    ka::key_pair{{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
                                  0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f}}};
            ka::gate g0{
                    ka::key_pair{{0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
                                  0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f}}};

            ka::gate_base_key g0_bk{0x70, 0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77, 0x78, 0x79, 0x7a, 0x7b, 0x7c, 0x7d, 0x7e, 0x7f,
                                   0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88, 0x89, 0x8a, 0x8b, 0x8c, 0x8d, 0x8e, 0x8f};

            test_p2p loopback{};

            ka::p2p::secure_initiator initiator{loopback, g0.keys()};
            ka::p2p::secure_target target{loopback, km.keys()};

            test_bundle() {
                std::thread t{[&]() {
                    TEST_ASSERT(target.handshake(5s));
                }};
                TEST_ASSERT(initiator.handshake(5s));
                t.join();
            }
        };

        struct assertive_local_gate : public test_bundle, public ka::p2p::v0::local_gate {
            assertive_local_gate()
                : test_bundle{},
                  ka::p2p::v0::local_gate{test_bundle::initiator, g0} {}

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
                return ka::p2p::v0::registration_info{ka::gate_id{32}, ka::pub_key{g0.keys().raw_pk()}};
            }

            ka::p2p::r<ka::gate_base_key> register_gate(ka::gate_id requested_id) override {
                TEST_ASSERT(requested_id == ka::gate_id{13});
                return test_bundle::g0_bk;
            }

            ka::p2p::r<> reset_gate() override {
                return mlab::result_success;
            }
        };


    }// namespace

    void test_p2p() {
        assertive_local_gate lg{};
        ka::p2p::v0::remote_gate rg{lg.target};

        auto trigger_test = [&]() {
            {
                auto r = rg.get_update_settings();
                TEST_ASSERT(r);
                if (r) {
                    TEST_ASSERT(not r->enable_automatic_update);
                    TEST_ASSERT(r->update_channel == "Foo bar");
                }
            }
            {
                auto r = rg.set_update_settings("The Channel", true);
                TEST_ASSERT(r);
            }
            {
                auto r = rg.get_wifi_status();
                TEST_ASSERT(r);
                if (r) {
                    TEST_ASSERT(r->ssid == "Nope");
                    TEST_ASSERT(not r->operational);
                }
            }
            {
                auto r = rg.connect_wifi("Test SSID", "Test Password");
                TEST_ASSERT(r);
                if (r) {
                    TEST_ASSERT(not *r);
                }
            }
            {
                auto r = rg.get_registration_info();
                TEST_ASSERT(r);
                if (r) {
                    TEST_ASSERT(r->id == ka::gate_id{32});
                    TEST_ASSERT(r->km_pk.raw_pk() == lg.g0.keys().raw_pk());
                }
            }
            {
                auto r = rg.register_gate(ka::gate_id{13});
                TEST_ASSERT(r);
                if (r) {
                    TEST_ASSERT(*r == lg.g0_bk);
                }
            }
            rg.bye();
        };

        std::thread t{trigger_test};
        lg.serve_loop();
        t.join();
    }
}// namespace ut