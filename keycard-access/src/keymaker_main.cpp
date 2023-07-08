//
// Created by spak on 6/13/23.
//

#include "keymaker_main.hpp"

#include <desfire/fs.hpp>
#include <desfire/tag_responder.hpp>
#include <ka/keymaker.hpp>
#include <ka/member_token.hpp>
#include <ka/p2p_ops.hpp>
#include <mlab/strutils.hpp>

#define LOG_PFX "KA-KM"

namespace ka {

    namespace {

        [[nodiscard]] auto make_keymaker() {
            key_pair kp{};
            /**
             * @todo This should not happen in real life.
             */

            ESP_LOGE("KA", "Overriding public key for testing purposes!");
            kp.generate_from_pwhash("foobar");
            return keymaker{kp};
        }

        struct keymaker_responder final : public ka::member_token_responder {
            ka::keymaker km;

            keymaker_responder() : km{make_keymaker()} {}

            desfire::result<> interact_with_token_internal(ka::member_token &token) {
                const ka::identity unique_id{{}, "Holder", "Publisher"};
                if (const auto r_deployed = token.is_deployed_correctly(km); r_deployed) {
                    ESP_LOGI(LOG_PFX, "Token was deployed.");
                    bool all_gates_were_enrolled = true;
                    for (auto const &cfg : km.gate_configs()) {
                        if (const auto r_enrolled = token.is_gate_enrolled_correctly(km, cfg); r_enrolled) {
                            if (r_enrolled->first) {
                                ESP_LOGI(LOG_PFX, "Gate %lu was already enrolled.", std::uint32_t(cfg.id));
                                continue;
                            }
                        } else if (r_enrolled.error() != desfire::error::app_not_found and
                                   r_enrolled.error() != desfire::error::file_not_found) {
                            if (ka::member_token::has_custom_meaning(r_enrolled.error())) {
                                ESP_LOGW(LOG_PFX, "Invalid gate enrollment: %s", ka::member_token::describe(r_enrolled.error()));
                                continue;
                            }
                            return r_enrolled.error();
                        }
                        all_gates_were_enrolled = false;
                        TRY(token.enroll_gate(km, cfg, unique_id))
                        ESP_LOGI(LOG_PFX, "I just enrolled gate %lu", std::uint32_t(cfg.id));
                    }
                    if (all_gates_were_enrolled) {
                        ESP_LOGI(LOG_PFX, "All gates were already enrolled, I'll format this PICC.");
                        /**
                         * @todo Use a method of keymaker and not direct access to keys
                         */
                        const auto rkey = km.keys().derive_token_root_key(*r_deployed);
                        TRY(desfire::fs::login_app(token.tag(), desfire::root_app, rkey))
                        TRY(token.tag().format_picc())
                        TRY(desfire::fs::login_app(token.tag(), desfire::root_app, rkey))
                        TRY(token.tag().change_key(desfire::key<desfire::cipher_type::des>{}))
                    }
                } else if (ka::member_token::has_custom_meaning(r_deployed.error())) {
                    ESP_LOGI(LOG_PFX, "Token deploy status: %s", ka::member_token::describe(r_deployed.error()));
                    ESP_LOGI(LOG_PFX, "Attempting deploy.");
                    TRY(token.deploy(km, unique_id))
                } else {
                    return r_deployed.error();
                }
                return mlab::result_success;
            }

            pn532::post_interaction interact_with_token(ka::member_token &token) override {
                const bool success = bool(interact_with_token_internal(token));
                ESP_LOG_LEVEL_LOCAL((success ? ESP_LOG_INFO : ESP_LOG_ERROR), LOG_PFX, "Interaction complete.");
                return pn532::post_interaction::reject;
            }
        };

    }// namespace

    void keymaker_main(pn532::scanner &scanner) {
        keymaker_responder responder{};
        scanner.loop(responder, false /* already performed */);
    }
}// namespace ka