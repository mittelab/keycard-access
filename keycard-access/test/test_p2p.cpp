//
// Created by spak on 7/6/23.
//

#include "test_p2p.hpp"
#include "test_bundle.hpp"
#include <chrono>
#include <desfire/esp32/utils.hpp>
#include <ka/gpio_auth_responder.hpp>
#include <ka/keymaker.hpp>
#include <ka/p2p_ops.hpp>
#include <ka/rpc.hpp>
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
    }// namespace

    struct secure_p2p_loopback {
        std::shared_ptr<ka::p2p::secure_initiator> initiator;
        std::shared_ptr<ka::p2p::secure_target> target;

        secure_p2p_loopback(std::shared_ptr<p2p_loopback> loop, ka::key_pair const &km_keys, ka::key_pair const &g_keys)
            : initiator{std::make_shared<ka::p2p::secure_initiator>(loop, g_keys)},
              target{std::make_shared<ka::p2p::secure_target>(loop, km_keys)} {
            std::thread t{[&]() {
                TEST_ASSERT(initiator->handshake(5s));
            }};
            TEST_ASSERT(target->handshake(5s));
            t.join();
        }

        secure_p2p_loopback(std::shared_ptr<p2p_loopback> loop, ka::keymaker const &km, ka::gate const &g) : secure_p2p_loopback{std::move(loop), km.keys(), g.keys()} {}
    };

    namespace {
        struct assertive_local_gate : public ka::p2p::v0::local_gate {
            using local_gate::local_gate;

            ka::p2p::r<ka::p2p::gate_update_config> get_update_settings() override {
                return ka::p2p::gate_update_config{"Foo bar", false};
            }

            ka::p2p::r<> set_update_settings(std::string_view update_channel, bool automatic_updates) override {
                TEST_ASSERT(update_channel == "The Channel");
                TEST_ASSERT(automatic_updates);
                return mlab::result_success;
            }

            ka::p2p::r<ka::p2p::gate_wifi_status> get_wifi_status() override {
                return ka::p2p::gate_wifi_status{"Nope", false};
            }

            ka::p2p::r<bool> connect_wifi(std::string_view ssid, std::string_view password) override {
                TEST_ASSERT(ssid == "Test SSID");
                TEST_ASSERT(password == "Test Password");
                return false;
            }

            ka::p2p::r<ka::p2p::gate_registration_info> get_registration_info() override {
                return ka::p2p::gate_registration_info{ka::gate_id{32}, g().public_info().pk, g().public_info().pk};
            }

            ka::p2p::r<ka::gate_base_key> register_gate(ka::gate_id requested_id) override {
                TEST_ASSERT(requested_id == ka::gate_id{13});
                return bundle.g0_bk;
            }

            ka::p2p::r<> reset_gate() override {
                return ka::p2p::error::unauthorized;
            }

            ka::p2p::r<ka::release_info> check_for_updates() override {
                return ka::release_info{semver::version{1, 2, 3}, "https://foo.bar"};
            }

            ka::p2p::r<ka::update_status> is_updating() override {
                return ka::update_status{"https://foo.bar"};
            }

            ka::p2p::r<ka::release_info> update_now() override {
                return ka::release_info{semver::version{1, 2, 3}, "https://foo.bar"};
            }

            ka::p2p::r<> update_manually(std::string_view fw_url) override {
                TEST_ASSERT(fw_url == "https://foo.bar");
                return mlab::result_success;
            }

            ka::p2p::r<> set_backend_url(std::string_view url, std::string_view api_key) override {
                TEST_ASSERT(url == "https://back.end");
                TEST_ASSERT(api_key == "deadbeef");
                return mlab::result_success;
            }

            ka::p2p::r<ka::gpio_responder_config> get_gpio_config() override {
                return ka::gpio_responder_config{GPIO_NUM_13, false, 100ms};
            }

            ka::p2p::r<> set_gpio_config(ka::gpio_responder_config cfg) override {
                TEST_ASSERT(cfg.gpio == GPIO_NUM_14);
                TEST_ASSERT(cfg.level == true);
                TEST_ASSERT(cfg.hold_time == 200ms);
                return mlab::result_success;
            }

            ka::p2p::r<std::string> get_backend_url() override {
                return std::string{"https://back.end"};
            }
        };


    }// namespace

    void test_p2p_comm() {
        ka::gate g{bundle.g0_kp};
        ka::keymaker km{bundle.km_kp};
        auto base_loop = std::make_shared<p2p_loopback>();
        secure_p2p_loopback loop{base_loop, km, g};
        assertive_local_gate lg{*loop.initiator, g};
        ka::p2p::v0::remote_gate rg{*loop.target};

        TEST_ASSERT(loop.initiator->did_handshake());
        TEST_ASSERT(loop.target->did_handshake());

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
            ESP_LOGI("UT", "Testing %s", "wifi_connect");
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
                TEST_ASSERT(r->pk == bundle.g0_kp);
                TEST_ASSERT(r->keymaker_pk == bundle.g0_kp);
            }
        }
        {
            ESP_LOGI("UT", "Testing %s", "gate_add");
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

        {
            ESP_LOGI("UT", "Testing %s", "check_for_updates");
            auto r = rg.check_for_updates();
            TEST_ASSERT(r);
            if (r) {
                TEST_ASSERT((r->semantic_version == semver::version{1, 2, 3}));
                TEST_ASSERT(r->firmware_url == "https://foo.bar");
            }
        }
        {
            ESP_LOGI("UT", "Testing %s", "is_updating");
            auto r = rg.is_updating();
            TEST_ASSERT(r);
            if (r) {
                TEST_ASSERT(r->updating_from);
                if (r->updating_from) {
                    TEST_ASSERT(*r->updating_from == "https://foo.bar");
                }
            }
        }
        {
            ESP_LOGI("UT", "Testing %s", "update_now");
            auto r = rg.update_now();
            TEST_ASSERT(r);
            if (r) {
                TEST_ASSERT((r->semantic_version == semver::version{1, 2, 3}));
                TEST_ASSERT(r->firmware_url == "https://foo.bar");
            }
        }
        {
            ESP_LOGI("UT", "Testing %s", "update_manually");
            auto r = rg.update_manually("https://foo.bar");
            TEST_ASSERT(r);
        }
        {
            ESP_LOGI("UT", "Testing %s", "set_backend_url");
            auto r = rg.set_backend_url("https://back.end", "deadbeef");
            TEST_ASSERT(r);
        }
        {
            ESP_LOGI("UT", "Testing %s", "get_gpio_config");
            auto r = rg.get_gpio_config();
            TEST_ASSERT(r);
            if (r) {
                TEST_ASSERT(r->gpio == GPIO_NUM_13);
                TEST_ASSERT(r->level == false);
                TEST_ASSERT(r->hold_time == 100ms);
            }
        }
        {
            ESP_LOGI("UT", "Testing %s", "set_gpio_config");
            auto r = rg.set_gpio_config(ka::gpio_responder_config{GPIO_NUM_14, true, 200ms});
            TEST_ASSERT(r);
        }
        {
            ESP_LOGI("UT", "Testing %s", "get_backend_url");
            auto r = rg.get_backend_url();
            TEST_ASSERT(r);
            if (r) {
                TEST_ASSERT(*r == "https://back.end");
            }
        }

        rg.bye();

        t.join();
    }

    void test_p2p_registration() {
        desfire::esp32::suppress_log suppress{ESP_LOG_ERROR, {"GATE", "P2P"}};

        ka::keymaker km1{bundle.km_kp};
        ka::keymaker km2{ka::key_pair{ka::pwhash, "foobar"}};
        ka::gate g{bundle.g0_kp};

        auto base_loop1 = std::make_shared<p2p_loopback>();
        auto base_loop2 = std::make_shared<p2p_loopback>();

        secure_p2p_loopback loop1{base_loop1, km1, g};
        secure_p2p_loopback loop2{base_loop2, km2, g};

        ka::p2p::v0::remote_gate rg1{*loop1.target};
        ka::p2p::v0::local_gate lg1{*loop1.initiator, g};

        ka::p2p::v0::remote_gate rg2{*loop2.target};
        ka::p2p::v0::local_gate lg2{*loop2.initiator, g};

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

    namespace {
        struct rpc_test {
            int multiplier = 4;

            [[nodiscard]] int multiply(int x) const {
                return x * multiplier;
            }

            void increase_multiplier() {
                ++multiplier;
            }
        };
    }// namespace

    void test_rpc() {
        rpc_test local_instance{-4};
        rpc_test remote_instance{4};

        auto loop = std::make_shared<p2p_loopback>();

        ka::rpc::bridge local_bridge{std::make_unique<ka::p2p::target_bridge_interface>(loop)};
        ka::rpc::bridge remote_bridge{std::make_unique<ka::p2p::initiator_bridge_interface>(loop)};

        local_bridge.register_command(&rpc_test::multiply, local_instance);
        local_bridge.register_command(&rpc_test::increase_multiplier, local_instance);
        local_bridge.register_command(&ka::rpc::bridge::serve_stop, local_bridge);

        remote_bridge.register_command(&rpc_test::multiply, remote_instance);
        remote_bridge.register_command(&rpc_test::increase_multiplier, remote_instance);
        remote_bridge.register_command(&ka::rpc::bridge::serve_stop, remote_bridge);

        std::thread remote_serve{&ka::rpc::bridge::serve_loop, &remote_bridge};

        {
            auto r_mul = local_bridge.remote_invoke_unique(&rpc_test::multiply, 42);
            TEST_ASSERT(r_mul);
            if (r_mul) {
                TEST_ASSERT(*r_mul == 42 * 4);
            }

            auto r_inc = local_bridge.remote_invoke_unique(&rpc_test::increase_multiplier);
            TEST_ASSERT(r_inc);

            r_mul = local_bridge.remote_invoke_unique(&rpc_test::multiply, 42);
            TEST_ASSERT(r_mul);
            if (r_mul) {
                TEST_ASSERT(*r_mul == 42 * 5);
            }

            TEST_ASSERT(local_bridge.remote_invoke_unique(&ka::rpc::bridge::serve_stop));
            remote_serve.join();
        }


        std::thread local_serve{&ka::rpc::bridge::serve_loop, &local_bridge};

        {
            auto r_mul = remote_bridge.remote_invoke_unique(&rpc_test::multiply, 42);
            TEST_ASSERT(r_mul);
            if (r_mul) {
                TEST_ASSERT(*r_mul == 42 * -4);
            }

            auto r_inc = remote_bridge.remote_invoke_unique(&rpc_test::increase_multiplier);
            TEST_ASSERT(r_inc);

            r_mul = remote_bridge.remote_invoke_unique(&rpc_test::multiply, 42);
            TEST_ASSERT(r_mul);
            if (r_mul) {
                TEST_ASSERT(*r_mul == 42 * -3);
            }

            TEST_ASSERT(remote_bridge.remote_invoke_unique(&ka::rpc::bridge::serve_stop));
            local_serve.join();
        }
    }
}// namespace ut