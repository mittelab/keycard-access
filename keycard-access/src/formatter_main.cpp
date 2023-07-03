//
// Created by spak on 6/13/23.
//

#include "formatter_main.hpp"
#include <desfire/esp32/utils.hpp>
#include <desfire/fs.hpp>
#include <desfire/tag_responder.hpp>
#include <esp_log.h>
#include <ka/key_pair.hpp>
#include <ka/member_token.hpp>
#include <mlab/strutils.hpp>

#define LOG_PFX "KA-FMT"

namespace ka {
    namespace {

        struct format_mcformatface final : public desfire::tag_responder<desfire::esp32::default_cipher_provider> {
            ka::token_id current_id{};

            void on_activation(pn532::scanner &, pn532::scanned_target const &target) override {
                const auto s_id = mlab::data_to_hex_string(target.nfcid);
                ESP_LOGI("NFC", "Activated: %s target %s.", pn532::to_string(target.type), s_id.c_str());
            }

            void on_release(pn532::scanner &, pn532::scanned_target const &target) override {
                const auto s_id = mlab::data_to_hex_string(target.nfcid);
                ESP_LOGI("NFC", "Released: %s target %s.", pn532::to_string(target.type), s_id.c_str());
            }

            void on_leaving_rf(pn532::scanner &, pn532::scanned_target const &target) override {
                const auto s_id = mlab::data_to_hex_string(target.nfcid);
                ESP_LOGI("NFC", "Out of RF: %s target %s.", pn532::to_string(target.type), s_id.c_str());
            }

            void on_failed_scan(pn532::scanner &, pn532::channel_error err) override {
                ESP_LOGW("NFC", "Failed scan: %s", pn532::to_string(err));
            }

            pn532::post_interaction interact(pn532::scanner &scanner, pn532::scanned_target const &target) override {
                current_id = ka::id_from_nfc_id(target.nfcid);
                return desfire::tag_responder<desfire::esp32::default_cipher_provider>::interact(scanner, target);
            }

            static constexpr std::uint8_t secondary_keys_version = 0x10;
            static constexpr std::array<std::uint8_t, 8> secondary_des_key = {0x0, 0x2, 0x4, 0x6, 0x8, 0xa, 0xc, 0xe};
            static constexpr std::array<std::uint8_t, 16> secondary_des3_2k_key = {0x0, 0x2, 0x4, 0x6, 0x8, 0xa, 0xc, 0xe, 0x10, 0x12, 0x14, 0x16, 0x18, 0x1a, 0x1c, 0x1e};
            static constexpr std::array<std::uint8_t, 24> secondary_des3_3k_key = {0x0, 0x2, 0x4, 0x6, 0x8, 0xa, 0xc, 0xe, 0x10, 0x12, 0x14, 0x16, 0x18, 0x1a, 0x1c, 0x1e, 0x20, 0x22, 0x24, 0x26, 0x28, 0x2a, 0x2c, 0x2e};
            static constexpr std::array<std::uint8_t, 16> secondary_aes_key = {0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0xa, 0xb, 0xc, 0xd, 0xe, 0xf};

            [[nodiscard]] static ka::key_pair &test_key_pair() {
                static ka::key_pair _kp{{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
                                         0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f}};
                return _kp;
            }

            [[nodiscard]] static ka::key_pair &demo_key_pair() {
                static ka::key_pair _kp{ka::pwhash, "foobar"};
                return _kp;
            }

            desfire::result<> interact_with_tag_internal(desfire::tag &tag) const {
                const desfire::any_key default_k{desfire::cipher_type::des};
                const std::vector<desfire::any_key> keys_to_test = {
                        default_k,
                        test_key_pair().derive_token_root_key(current_id),
                        demo_key_pair().derive_token_root_key(current_id),
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
                return mlab::result_success;
            }

            pn532::post_interaction interact_with_tag(desfire::tag &tag) override {
                ESP_LOGI(LOG_PFX, "Beginning interaction.");
                const auto success = bool(interact_with_tag_internal(tag));
                ESP_LOG_LEVEL_LOCAL((success ? ESP_LOG_INFO : ESP_LOG_WARN), LOG_PFX, "Interaction complete.");
                return pn532::post_interaction::reject;
            }
        };

    }// namespace

    void format_mcformatface_main(pn532::scanner &scanner) {
        format_mcformatface responder{};
        scanner.loop(responder, false /* already performed */);
    }
}// namespace ka