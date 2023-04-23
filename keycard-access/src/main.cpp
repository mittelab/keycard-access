#include <desfire/esp32/utils.hpp>
#include <esp_log.h>
#include <freertos/FreeRTOS.h>
#include <freertos/task.h>
#include <ka/config.hpp>
#include <ka/gate.hpp>
#include <ka/p2p_ops.hpp>
#include <mlab/strutils.hpp>
#include <pn532/controller.hpp>
#include <pn532/esp32/hsu.hpp>
#include <neo/strip.hpp>
#include <neo/led.hpp>
#include <neo/gradient_fx.hpp>
#include <neo/any_fx.hpp>
#include <neo/timer.hpp>

static constexpr rmt_channel_t rmt_channel = RMT_CHANNEL_0;
static constexpr gpio_num_t strip_gpio_pin = GPIO_NUM_13;
static constexpr std::size_t strip_num_leds = 16;

using namespace std::chrono_literals;
using namespace neo::literals;

// Override the log prefix
#define LOG_PFX "KADEMO"
#define DESFIRE_FS_LOG_PREFIX LOG_PFX
#include <desfire/fs.hpp>

using namespace std::chrono_literals;

desfire::result<> try_hard_to_format(desfire::tag &tag, ka::token_id current_id) {
    static constexpr std::uint8_t secondary_keys_version = 0x10;
    static constexpr std::array<std::uint8_t, 8> secondary_des_key = {0x0, 0x2, 0x4, 0x6, 0x8, 0xa, 0xc, 0xe};
    static constexpr std::array<std::uint8_t, 16> secondary_des3_2k_key = {0x0, 0x2, 0x4, 0x6, 0x8, 0xa, 0xc, 0xe, 0x10, 0x12, 0x14, 0x16, 0x18, 0x1a, 0x1c, 0x1e};
    static constexpr std::array<std::uint8_t, 24> secondary_des3_3k_key = {0x0, 0x2, 0x4, 0x6, 0x8, 0xa, 0xc, 0xe, 0x10, 0x12, 0x14, 0x16, 0x18, 0x1a, 0x1c, 0x1e, 0x20, 0x22, 0x24, 0x26, 0x28, 0x2a, 0x2c, 0x2e};
    static constexpr std::array<std::uint8_t, 16> secondary_aes_key = {0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0xa, 0xb, 0xc, 0xd, 0xe, 0xf};

    const ka::key_pair test_key_pair{{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
                                      0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f}};
    const ka::key_pair demo_key_pair{ka::pwhash, "foobar"};

    const desfire::any_key default_k{desfire::cipher_type::des};
    const std::vector<desfire::any_key> keys_to_test = {
            default_k,
            test_key_pair.derive_token_root_key(current_id),
            demo_key_pair.derive_token_root_key(current_id),
            desfire::any_key{desfire::cipher_type::des3_2k},
            desfire::any_key{desfire::cipher_type::des3_3k},
            desfire::any_key{desfire::cipher_type::aes128},
            desfire::any_key{desfire::cipher_type::des, mlab::make_range(secondary_des_key), 0, secondary_keys_version},
            desfire::any_key{desfire::cipher_type::des3_2k, mlab::make_range(secondary_des3_2k_key), 0, secondary_keys_version},
            desfire::any_key{desfire::cipher_type::des3_3k, mlab::make_range(secondary_des3_3k_key), 0, secondary_keys_version},
            desfire::any_key{desfire::cipher_type::aes128, mlab::make_range(secondary_aes_key), 0, secondary_keys_version}};
    const auto s_nfcid = mlab::data_to_hex_string(current_id);
    ESP_LOGI(LOG_PFX, "Attempting to recover root key for ID %s", s_nfcid.c_str());
    TRY(tag.select_application());
    for (auto const &key : keys_to_test) {
        const auto key_body = key.get_packed_key_body();
        const auto s_key_body = mlab::data_to_hex_string(key_body);
        ESP_LOGI(LOG_PFX, "Trying %s...", s_key_body.c_str());
        auto suppress = desfire::esp32::suppress_log{DESFIRE_LOG_PREFIX};
        if (tag.authenticate(key)) {
            suppress.restore();
            ESP_LOGI(LOG_PFX, "Found the right key, changing to default.");
            TRY(tag.change_key(default_k));
            TRY(tag.authenticate(default_k));
            ESP_LOGI(LOG_PFX, "NFC ID: %s", s_nfcid.c_str());
            TRY_RESULT(tag.get_info()) {
                const auto s_serial = mlab::data_to_hex_string(r->serial_no);
                ESP_LOGI(LOG_PFX, "Serial: %s", s_nfcid.c_str());
            }
            TRY_RESULT(tag.get_card_uid()) {
                const auto s_card_uid = mlab::data_to_hex_string(*r);
                ESP_LOGI(LOG_PFX, "CardID: %s", s_nfcid.c_str());
            }
            TRY_RESULT(tag.get_application_ids()) {
                if (r->empty()) {
                    ESP_LOGI(LOG_PFX, "  Apps: none");
                } else {
                    for (std::size_t i = 0; i < r->size(); ++i) {
                        ESP_LOGI(LOG_PFX, "  %s %2d. %02x%2x%2x", (i == 0 ? "Apps:" : "     "), i + 1, (*r)[i][0], (*r)[i][1], (*r)[i][2]);
                    }
                }
            }
            TRY(tag.format_picc());
            ESP_LOGI(LOG_PFX, "Formatted.");
            return mlab::result_success;
        }
    }
    ESP_LOGE(LOG_PFX, "I do not know the key...");
    return desfire::error::authentication_error;
}


namespace {
    const std::array<neo::gradient, 7> default_gradients = {
            neo::gradient{{0xff0000_rgb, 0xffff00_rgb, 0x00ff00_rgb, 0x00ffff_rgb, 0x0000ff_rgb, 0xff00ff_rgb, 0xff0000_rgb}},
            neo::gradient({0xcc0000_rgb, 0xcccc00_rgb, 0xcc0000_rgb}),
            neo::gradient({0xcccc00_rgb, 0x00cc00_rgb, 0xcccc00_rgb}),
            neo::gradient({0x00cc00_rgb, 0x00cccc_rgb, 0x00cc00_rgb}),
            neo::gradient({0x00cccc_rgb, 0x0000cc_rgb, 0x00cccc_rgb}),
            neo::gradient({0x0000cc_rgb, 0xcc00cc_rgb, 0x0000cc_rgb}),
            neo::gradient({0xcc00cc_rgb, 0xcc0000_rgb, 0xcc0000_rgb})
    };
}

class neopx_status {
    neo::rmt_manager _manager;
    neo::strip<neo::grb_led> _strip;
    neo::any_fx _fx;
    neo::steady_timer _timer;

public:

    neopx_status()
        : _manager{neo::make_rmt_config(rmt_channel, strip_gpio_pin), true},
          _strip{_manager, neo::controller::ws2812_800khz, strip_num_leds},
          _fx{},
          _timer{32ms, _fx.make_steady_timer_callback(_strip, _manager), 0}
    {
        if (const auto err = _strip.transmit(_manager, true); err != ESP_OK) {
            ESP_LOGE("NEO", "Trasmit failed with status %s", esp_err_to_name(err));
        }
        _timer.start();
    }

    void set_spinner(neo::rgb c) {
        _fx.g_fx().set_gradient(neo::gradient{{0x0_rgb, c}});
        _fx.g_fx().set_duration(2s);
        _fx.g_fx().set_repeats(1.f);
        _fx.set_type(neo::fx_type::gradient);
    }

    void set_pulse_solid(neo::rgb c, float low = 0.f, float high = 1.f) {
        neo::rgb lo_col = c, hi_col = c;
        lo_col.blend(0x0_rgb, 1.f - low);
        hi_col.blend(0x0_rgb, 1.f - high);
        _fx.m_fx().set_matrix({lo_col, hi_col, lo_col}, 1);
        _fx.m_fx().set_duration_x(0s);
        _fx.m_fx().set_duration_y(4s);
        _fx.set_type(neo::fx_type::matrix);
    }

    void set_pulse_gradient(neo::gradient const &g, float low = 0.f, float high = 1.f) {
        const auto n = _strip.size();
        std::vector<neo::rgb> matrix;
        matrix.reserve(3 * n);
        matrix.resize(n);
        g.sample_uniform(1.f / float(n), 0.f, matrix);
        matrix.resize(3 * n);
        std::copy_n(std::begin(matrix), n, std::begin(matrix) + signed(n));
        for (std::size_t i = 0; i < n; ++i) {
            matrix[i].blend(0x0_rgb, 1.f - low);
            matrix[n + i].blend(0x0_rgb, 1.f - high);
        }
        std::copy_n(std::begin(matrix), n, std::begin(matrix) + 2 * signed(n));

        _fx.m_fx().set_matrix(std::move(matrix), n);
        _fx.m_fx().set_duration_x(0s);
        _fx.m_fx().set_duration_y(4s);
        _fx.set_type(neo::fx_type::matrix);
    }

    void set_solid(neo::rgb c) {
        _fx.s_fx().set_color(c);
        _fx.set_type(neo::fx_type::solid);
    }

    void set_solid(neo::gradient g) {
        _fx.g_fx().set_gradient(std::move(g));
        _fx.g_fx().set_duration(0s);
        _fx.g_fx().set_repeats(1.f);
        _fx.set_type(neo::fx_type::gradient);
    }
};

struct fiera_gate_responder final : public ka::gate_responder {
    neopx_status &s;

    fiera_gate_responder(ka::gate &g, neopx_status &s_) : ka::gate_responder{g}, s{s_} {}

    void on_authentication_success(ka::identity const &id) override {
        if (id.holder.size() >= 6 and id.holder.substr(0, 5) == "Token") {
            const auto snum = id.holder.substr(5);
            const auto *begin = snum.c_str();
            char *end = nullptr;
            const auto idx = std::strtoul(snum.c_str(), &end, 10);
            if (end != nullptr and begin != end) {
                s.set_solid(default_gradients[idx % default_gradients.size()]);
            } else {
                s.set_solid(0xaaaaaa_rgb);
            }
        } else {
            s.set_solid(0xcc0000_rgb);
        }
    }

    void on_authentication_fail(desfire::error auth_error, bool might_be_tampering) override {
        s.set_solid(0xcc0000_rgb);
    }

    void on_activation(pn532::scanner &scanner, pn532::scanned_target const &target) override {
        s.set_spinner(0xffffff_rgb);
    }

    void on_leaving_rf(pn532::scanner &scanner, pn532::scanned_target const &target) override {
        s.set_spinner(0xaaaaaa_rgb);
    }
};


struct fiera_keymaker_responder final : public ka::member_token_responder {
    ka::keymaker &km;
    unsigned token_idx;
    ka::gate_config cfg;
    neopx_status &s;

    explicit fiera_keymaker_responder(ka::keymaker &km_, ka::gate_config cfg_, neopx_status &s_) : km{km_}, token_idx{0}, cfg{cfg_}, s{s_} {}

    desfire::result<> interact_with_token_internal(ka::member_token &token) {
        ka::identity who;
        TRY_RESULT(token.get_id()) {
            who.id = *r;
        }
        who.publisher = "Mittelab";
        {
            char buffer[16];
            std::sprintf(buffer, "Token%d", token_idx);
            who.holder = buffer;
        }
        ESP_LOGI(LOG_PFX, "Programming token as: %s", who.holder.c_str());

        ESP_LOGI(LOG_PFX, "Formatting...");
        TRY(try_hard_to_format(token.tag(), who.id))

        ESP_LOGI(LOG_PFX, "Attempting deploy...");
        TRY(token.deploy(km, who))
        TRY(token.enroll_gate(km, cfg, who))
        ESP_LOGI(LOG_PFX, "Enrolled correctly!");
        ++token_idx;

        return mlab::result_success;
    }

    pn532::post_interaction interact_with_token(ka::member_token &token) override {
        const bool success = bool(interact_with_token_internal(token));
        ESP_LOG_LEVEL_LOCAL((success ? ESP_LOG_INFO : ESP_LOG_ERROR), LOG_PFX, "Interaction complete.");
        if (success) {
            s.set_solid(0x00cc00_rgb);
        } else {
            s.set_solid(0xcc0000_rgb);
        }
        return pn532::post_interaction::reject;
    }

    void on_activation(pn532::scanner &scanner, pn532::scanned_target const &target) override {
        s.set_spinner(0xaaaaaa_rgb);
    }

    void on_leaving_rf(pn532::scanner &scanner, pn532::scanned_target const &target) override {
        s.set_pulse_gradient(default_gradients[token_idx % default_gradients.size()], 0.2, 0.6);
    }
};


extern "C" void app_main() {
    neopx_status s;
    s.set_pulse_solid(0xffffff_rgb, 0.2, 0.6);

    pn532::esp32::hsu_channel hsu_chn{ka::pinout::uart_port, ka::pinout::uart_config, ka::pinout::pn532_hsu_tx, ka::pinout::pn532_hsu_rx};
    pn532::controller controller{hsu_chn};

    ka::keymaker km{};
    km._kp.generate_from_pwhash("foobar");
    ka::gate g{};
    g.configure_demo_from_pwhash("foobar2", ka::gate_id{0}, "Fiera", ka::pub_key{km.keys().raw_pk()});

    pn532::scanner scanner{controller};

    if (not scanner.init_and_test_controller()) {
        ESP_LOGE(LOG_PFX, "Power cycle the device to try again.");
        return;
    }
    ESP_LOGI(LOG_PFX, "Self-test passed.");


    ESP_LOGI(LOG_PFX, "Waiting 2s to ensure the serial is attached and visible...");
    vTaskDelay(pdMS_TO_TICKS(2000));
    int choice = 1;
    while (choice == 0) {
        std::printf("Select operation mode of the demo:\n");
        std::printf("\t1. Gate\n");
        std::printf("\t2. Keymaker\n");
        std::printf("> ");
        while (std::scanf("%d", &choice) != 1) {
            vTaskDelay(pdMS_TO_TICKS(100));
        }
        if (choice < 1 or choice > 3) {
            std::printf("Insert '1' or '2' or '3'.");
            choice = 0;
        }
    }
    std::printf("\n");

    if (choice == 1) {
        std::printf("Acting as gate.\n");
        fiera_gate_responder responder{g, s};
        s.set_spinner(0xaaaaaa_rgb);
        scanner.loop(responder, false /* already performed */);
    } else if (choice == 2) {
        std::printf("Acting as keymaker.\n");
        s.set_pulse_gradient(default_gradients[0], 0.2, 0.6);
        fiera_keymaker_responder km_responder{km, ka::gate_config{g.id(), ka::pub_key{g.keys().raw_pk()}, g.app_base_key()}, s};
        scanner.loop(km_responder, false /* already performed */);
    }

    vTaskSuspend(nullptr);
}
