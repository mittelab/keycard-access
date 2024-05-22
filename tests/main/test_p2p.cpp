//
// Created by spak on 7/6/23.
//

#include "test_bundle.hpp"
#include <catch/catch.hpp>
#include <chrono>
#include <desfire/esp32/utils.hpp>
#include <ka/gpio_auth_responder.hpp>
#include <ka/keymaker.hpp>
#include <ka/p2p_ops.hpp>
#include <ka/rpc.hpp>
#include <ka/secure_p2p.hpp>
#include <pn532/p2p.hpp>

using namespace std::chrono_literals;

namespace ut {

    namespace {
        using ms = std::chrono::milliseconds;

        struct p2p_loopback final : public pn532::p2p::initiator, public pn532::p2p::target {
            mlab::bin_data i2t_data;
            mlab::bin_data t2i_data;

            std::atomic<bool> i2t_available{false};
            std::atomic<bool> t2i_available{false};

            std::mutex i2t_mutex{};
            std::mutex t2i_mutex{};

            pn532::result<mlab::bin_data> receive(ms timeout) override {
                mlab::reduce_timeout rt{timeout};
                while (rt) {
                    if (i2t_available) {
                        std::unique_lock<std::mutex> lock{i2t_mutex};
                        i2t_available = false;
                        return i2t_data;
                    }
                    std::this_thread::sleep_for(10ms);
                }
                return pn532::channel_error::timeout;
            }

            pn532::result<> send(mlab::bin_data const &data_to_send, ms) override {
                if (t2i_available) {
                    ESP_LOGE("UT", "No one has consumed this target data!");
                    return pn532::channel_error::timeout;
                }
                std::unique_lock<std::mutex> lock{t2i_mutex, std::try_to_lock};
                if (not lock) {
                    ESP_LOGE("UT", "No one else other than this thread should be locking t2i_mutex.");
                    return pn532::channel_error::timeout;
                }
                t2i_data = data_to_send;
                t2i_available = true;
                return mlab::result_success;
            }

            pn532::result<mlab::bin_data> communicate(mlab::bin_data const &data_to_send, ms timeout) override {
                {
                    if (i2t_available) {
                        ESP_LOGE("UT", "No one has consumed initiator target data!");
                        return pn532::channel_error::timeout;
                    }
                    std::unique_lock<std::mutex> lock{i2t_mutex, std::try_to_lock};
                    if (not lock) {
                        ESP_LOGE("UT", "No one else other than this thread should be locking i2t_mutex.");
                        return pn532::channel_error::timeout;
                    }
                    i2t_data = data_to_send;
                    i2t_available = true;
                }
                mlab::reduce_timeout rt{timeout};
                while (rt) {
                    if (t2i_available) {
                        std::unique_lock<std::mutex> lock{t2i_mutex};
                        t2i_available = false;
                        return t2i_data;
                    }
                    std::this_thread::sleep_for(10ms);
                }
                return pn532::channel_error::timeout;
            }
        };
    }// namespace

    struct secure_p2p_loopback {
        std::shared_ptr<ka::p2p::secure_initiator> initiator;
        std::shared_ptr<ka::p2p::secure_target> target;

        secure_p2p_loopback(std::shared_ptr<p2p_loopback> const &loop, ka::key_pair const &km_keys, ka::key_pair const &g_keys)
            : initiator{std::make_shared<ka::p2p::secure_initiator>(loop, g_keys)},
              target{std::make_shared<ka::p2p::secure_target>(loop, km_keys)} {
            std::thread t{[&]() {
                CHECK(initiator->handshake(5s));
            }};
            CHECK(target->handshake(5s));
            t.join();
        }

        secure_p2p_loopback(std::shared_ptr<p2p_loopback> const &loop, ka::keymaker const &km, ka::gate const &g)
            : secure_p2p_loopback{loop, km.keys(), g.keys()} {}
    };

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

    TEST_CASE("0010 RPC") {
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
            CHECKED_IF_FAIL(r_mul) {
                CHECK(*r_mul == 42 * 4);
            }

            auto r_inc = local_bridge.remote_invoke_unique(&rpc_test::increase_multiplier);
            CHECK(r_inc);

            r_mul = local_bridge.remote_invoke_unique(&rpc_test::multiply, 42);
            CHECKED_IF_FAIL(r_mul) {
                CHECK(*r_mul == 42 * 5);
            }

            CHECK(local_bridge.remote_invoke_unique(&ka::rpc::bridge::serve_stop));
            remote_serve.join();
        }


        std::thread local_serve{&ka::rpc::bridge::serve_loop, &local_bridge};

        {
            auto r_mul = remote_bridge.remote_invoke_unique(&rpc_test::multiply, 42);
            CHECKED_IF_FAIL(r_mul) {
                CHECK(*r_mul == 42 * -4);
            }

            auto r_inc = remote_bridge.remote_invoke_unique(&rpc_test::increase_multiplier);
            CHECK(r_inc);

            r_mul = remote_bridge.remote_invoke_unique(&rpc_test::multiply, 42);
            CHECKED_IF_FAIL(r_mul) {
                CHECK(*r_mul == 42 * -3);
            }

            CHECK(remote_bridge.remote_invoke_unique(&ka::rpc::bridge::serve_stop));
            local_serve.join();
        }
    }

    TEST_CASE("0011 Gate RPC") {
        ka::gate g{bundle.g0_kp};
        ka::keymaker km{bundle.km_kp};
        auto base_loop = std::make_shared<p2p_loopback>();
        secure_p2p_loopback loop{base_loop, km, g};

        ka::p2p::local_gate lg{g, loop.initiator};
        ka::p2p::remote_gate rg{loop.target};

        CHECK(loop.initiator->did_handshake());
        CHECK(loop.target->did_handshake());

        ka::wifi::instance().set_max_attempts(1);

        std::thread local_serve{&ka::p2p::local_gate::serve_loop, &lg};

        {
            ESP_LOGI("UT", "Testing %s", "get_fw_info");
            auto r = rg.get_fw_info();
            CHECKED_IF_FAIL(r) {
                auto orig = g.get_firmware_info();
                CHECK(r->semantic_version == orig.semantic_version);
                CHECK(r->commit_info == orig.commit_info);
                CHECK(r->app_name == orig.app_name);
                CHECK(r->platform_code == orig.platform_code);
            }
        }

        {
            ESP_LOGI("UT", "Testing %s", "get_update_settings");
            auto r = rg.get_update_settings();
            CHECKED_IF_FAIL(r) {
                CHECK(r->update_channel == g.update_channel());
                CHECK(r->enable_automatic_update == g.updates_automatically());
            }
        }

        {
            ESP_LOGI("UT", "Testing %s", "get_wifi_status");
            desfire::esp32::suppress_log suppress{ESP_LOG_NONE, {"KA-WIFI"}};
            auto r = rg.get_wifi_status();
            CHECKED_IF_FAIL(r) {
                auto orig_ssid = g.wifi_get_ssid();
                if (orig_ssid) {
                    CHECK(r->ssid == *orig_ssid);
                    CHECK(r->operational == g.wifi_test());
                } else {
                    CHECK(r->ssid.empty());
                    CHECK(not r->operational);
                }
            }
        }

        {
            ESP_LOGI("UT", "Testing %s", "is_updating");
            auto r = rg.is_updating();
            CHECKED_IF_FAIL(r) {
                auto orig = g.is_updating();
                CHECK(r->updating_from == orig.updating_from);
            }
        }

        {
            ESP_LOGI("UT", "Testing %s", "get_gpio_config");
            auto r = rg.get_gpio_config();
            CHECKED_IF_FAIL(r) {
                auto orig = ka::gpio_responder_config::get_global_config();
                CHECK(r->level == orig.level);
                CHECK(r->gpio == orig.gpio);
                CHECK(r->hold_time == orig.hold_time);
            }
        }

        {
            ESP_LOGI("UT", "Testing %s", "get_registration_info");
            auto r = rg.get_registration_info();
            CHECKED_IF_FAIL(r) {
                CHECK(r->keymaker_pk == g.keymaker_pk());
                CHECK(r->pk == g.public_info().pk);
                CHECK(r->id == g.public_info().id);
            }
        }

        {
            ESP_LOGI("UT", "Testing %s", "get_backend_url (future feature)");
            desfire::esp32::suppress_log suppress{ESP_LOG_NONE, {"P2P"}};
            auto r = rg.get_backend_url();
            CHECKED_IF_FAIL(r) {
                // So far is unimplemented.
                CHECK(r->empty());
            }
        }

        {
            ESP_LOGI("UT", "Testing %s", "check_for_updates");
            desfire::esp32::suppress_log suppress{ESP_LOG_NONE, {"KADEV"}};
            auto r = rg.check_for_updates();
            CHECKED_IF_FAIL(r) {
                CHECKED_IF_FAIL(*r) {
                    CHECK(((**r).semantic_version == semver::version{0, 0, 0, semver::prerelease::alpha, 0}));
                    CHECK((**r).firmware_url.empty());
                }
            }
        }

        {
            ESP_LOGI("UT", "Testing %s", "set_update_settings (noop in test)");
            desfire::esp32::suppress_log suppress{ESP_LOG_NONE, {"KADEV"}};
            auto r = rg.set_update_settings("https://foo.bar", true);
            CHECKED_IF_FAIL(r) {
                CHECKED_IF_FAIL(not *r) {
                    CHECK(r->error() == ka::p2p::error::invalid_argument);
                }
            }
        }

        {
            ESP_LOGI("UT", "Testing %s", "update_manually (noop in test)");
            desfire::esp32::suppress_log suppress{ESP_LOG_NONE, {"KADEV"}};
            auto r = rg.update_manually("https://foo.bar");
            CHECKED_IF_FAIL(r) {
                CHECK(*r);
            }
        }

        {
            ESP_LOGI("UT", "Testing %s", "update_now (noop in test)");
            desfire::esp32::suppress_log suppress{ESP_LOG_NONE, {"KADEV"}};
            auto r = rg.update_now();
            CHECKED_IF_FAIL(r) {
                CHECKED_IF_FAIL(*r) {
                    CHECK(((**r).semantic_version == semver::version{0, 0, 0, semver::prerelease::alpha, 0}));
                    CHECK((**r).firmware_url.empty());
                }
            }
        }

        {
            ESP_LOGI("UT", "Testing %s", "connect_wifi (non existent ssid)");
            desfire::esp32::suppress_log suppress{ESP_LOG_NONE, {"KA-WIFI"}};
            auto r = rg.connect_wifi("non existent", "wifi");
            CHECK(ka::wifi::instance().get_ssid() == "non existent");
            CHECKED_IF_FAIL(r) {
                CHECKED_IF_FAIL(*r) {
                    CHECK(not **r);
                }
            }
        }

        {
            ESP_LOGI("UT", "Testing %s", "register_gate");
            auto r = rg.register_gate(ka::gate_id{42});
            CHECK(r);
            // Test that it fails afterward
            r = rg.register_gate(ka::gate_id{42});
            CHECKED_IF_FAIL(r) {
                CHECKED_IF_FAIL(not *r) {
                    CHECK((*r).error() == ka::p2p::error::invalid_operation);
                }
            }
        }

        {
            ESP_LOGI("UT", "Testing %s", "set_backend_url (future feature)");
            desfire::esp32::suppress_log suppress{ESP_LOG_NONE, {"P2P"}};
            auto r = rg.set_backend_url("foo", "bar");
            CHECKED_IF_FAIL(r) {
                CHECKED_IF_FAIL(not *r) {
                    CHECK(r->error() == ka::p2p::error::invalid_operation);
                }
            }
        }

        {
            ESP_LOGI("UT", "Testing %s", "set_gpio_config");
            auto r = rg.set_gpio_config(ka::gpio_responder_config{GPIO_NUM_MAX, false, 42ms});
            CHECKED_IF_FAIL(r) {
                CHECKED_IF_FAIL(*r) {
                    auto orig = ka::gpio_responder_config::get_global_config();
                    CHECK(orig.level == false);
                    CHECK(orig.hold_time == 42ms);
                    CHECK(orig.gpio == GPIO_NUM_MAX);
                }
            }
        }

        {
            ESP_LOGI("UT", "Testing %s", "reset_gate");
            desfire::esp32::suppress_log suppress{ESP_LOG_NONE, {"GATE"}};
            auto r = rg.reset_gate();
            CHECKED_IF_FAIL(r) {
                CHECK(*r);
            }
        }

        {
            ESP_LOGI("UT", "Testing %s", "set_backend_url (not configured)");
            desfire::esp32::suppress_log suppress{ESP_LOG_NONE, {"P2P"}};
            auto r = rg.set_backend_url("foo", "bar");
            CHECKED_IF_FAIL(r) {
                CHECKED_IF_FAIL(not *r) {
                    CHECK(r->error() == ka::p2p::error::invalid_operation);
                }
            }
        }

        {
            ESP_LOGI("UT", "Testing %s", "reset_gate (not configured)");
            desfire::esp32::suppress_log suppress{ESP_LOG_NONE, {"P2P"}};
            auto r = rg.reset_gate();
            CHECKED_IF_FAIL(r) {
                CHECKED_IF_FAIL(not *r) {
                    CHECK(r->error() == ka::p2p::error::invalid_operation);
                }
            }
        }

        CHECK(rg.bye());

        local_serve.join();
    }

    TEST_CASE("0012 RPC registration") {
        desfire::esp32::suppress_log suppress{ESP_LOG_ERROR, {"GATE", "P2P"}};

        ka::keymaker km1{bundle.km_kp};
        ka::keymaker km2{ka::key_pair{ka::pwhash, "foobar"}};
        ka::gate g{bundle.g0_kp};

        auto base_loop1 = std::make_shared<p2p_loopback>();
        auto base_loop2 = std::make_shared<p2p_loopback>();

        secure_p2p_loopback loop1{base_loop1, km1, g};
        secure_p2p_loopback loop2{base_loop2, km2, g};

        ka::p2p::remote_gate rg1{loop1.target};
        ka::p2p::local_gate lg1{g, loop1.initiator};

        ka::p2p::remote_gate rg2{loop2.target};
        ka::p2p::local_gate lg2{g, loop2.initiator};

        std::thread t1{[&]() { lg1.serve_loop(); }};
        std::thread t2{[&]() { lg2.serve_loop(); }};

        auto is_unauthorized = [](auto const &r) { return r and not *r and r->error() == ka::p2p::error::unauthorized; };
        auto is_invalid = [](auto const &r) { return r and not *r and r->error() == ka::p2p::error::invalid_operation; };

        // Do the setup with km1
        CHECK(rg1.get_fw_info());
        CHECK(rg1.register_gate(ka::gate_id{11}));
        CHECK(is_invalid(rg1.register_gate(ka::gate_id{11})));

        // Attempt to register with km2
        CHECK(rg2.get_fw_info());
        CHECK(is_invalid(rg2.register_gate(ka::gate_id{12})));
        CHECK(is_unauthorized(rg2.reset_gate()));
        CHECK(is_unauthorized(rg2.connect_wifi("foo", "bar")));
        CHECK(is_unauthorized(rg2.set_update_settings("foo", false)));

        // Reset with km1
        CHECK(rg1.reset_gate());
        CHECK(rg2.register_gate(ka::gate_id{11}));

        // Good.
        rg1.bye();
        rg2.bye();

        t1.join();
        t2.join();
    }

}// namespace ut