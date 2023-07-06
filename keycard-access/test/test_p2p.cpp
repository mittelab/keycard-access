//
// Created by spak on 7/6/23.
//

#include "test_p2p.hpp"
#include "test_bundle.hpp"
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

        struct p2p_loopback : public pn532::p2p::initiator, public pn532::p2p::target {
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

        struct loopback_bundle : test_bundle {
            p2p_loopback loopback{};

            ka::p2p::secure_initiator initiator{loopback, g0_uncfg.keys()};
            ka::p2p::secure_target target{loopback, km.keys()};

            loopback_bundle() {
                std::thread t{[&]() {
                    TEST_ASSERT(target.handshake(5s));
                }};
                TEST_ASSERT(initiator.handshake(5s));
                t.join();
            }
        };

        struct assertive_local_gate : public loopback_bundle, public ka::p2p::v0::local_gate {
            assertive_local_gate()
                : loopback_bundle{},
                  ka::p2p::v0::local_gate{initiator, g0_uncfg} {}

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
                return ka::p2p::v0::registration_info{ka::gate_id{32}, ka::pub_key{g0_uncfg.keys().raw_pk()}};
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

    void test_p2p_comm() {
        assertive_local_gate lg{};
        ka::p2p::v0::remote_gate rg{lg.target};

        auto trigger_test = [&]() {
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
                    TEST_ASSERT(r->km_pk.raw_pk() == lg.g0_uncfg.keys().raw_pk());
                }
            }
            {
                ESP_LOGI("UT", "Testing %s", "register_gate");
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