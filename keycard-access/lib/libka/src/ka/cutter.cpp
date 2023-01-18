//
// Created by g5pw on 18/01/23.
//

#include <esp_vfs_dev.h>

#include <chrono>

#include <desfire/esp32/cipher_provider.hpp>
#include <pn532/desfire_pcd.hpp>
#include <ka/data.hpp>
#include <ka/desfire_fs.hpp>
#include <ka/gate.hpp>
#include <ka/member_token.hpp>

#include <ka/cutter.hpp>

namespace ka {

    identity cutter::select_identity() {
        // get identity from somewhere
       return {
                .id = {},
                .holder = "surname,Srebrnic\nname,Aljaz\nsex,m\nmember_id,0007",
                .publisher = publisher,
        };
    }

    gate cutter::select_gate() {
       return {

       };
    }

    member_token cutter::find_card(pn532::controller &controller) {
        using namespace std::chrono_literals;
        using cipher_provider = desfire::esp32::default_cipher_provider;

        std::vector<identity> users{};

        ESP_LOGI("KTR", "Waiting for card");
        const auto r = controller.initiator_list_passive_kbps106_typea(1, 10s);

        if (not r or r->empty()) {
            ESP_LOGW("KTR", "No tag found, aborting");
        }

        const token_id current_target = util::id_from_nfc_id(r->front().info.nfcid);
        ESP_LOGI("KTR", "Found passive target with NFC ID:");
        ESP_LOG_BUFFER_HEX_LEVEL("KTR", current_target.data(), current_target.size(), ESP_LOG_INFO);
        auto tag = desfire::tag::make<cipher_provider>(controller, r->front().logical_index);
        return member_token{tag};
    }

    void cutter::loop(pn532::controller&& controller) {
        while (true) {
            printf("What to do?\n");
            printf("\t1) Cut a key (create a card)\n");
            printf("\t2) Configure key for gate\n");
            printf("\t3) Open a portal (configure a gate)\n");
            printf("\t4) Dump gate config\n");
            printf("\t5) Restore gate config\n");
            printf("Enter choice: ");

            int choice = 0;
            while (scanf("%d", &choice) != 1);

            switch(choice) {
                case 1:
                    cut_key(controller, select_identity());
                    break;
                case 2:
                    configure_key_for_gate(controller, select_gate());
                    break;
                case 3:
                    break;
                case 4:
                    break;
                case 5:
                    break;
                default:
                    printf("\nChoice not recognized!\n");
                    continue;
            }

            printf("You chose: %d\n", choice);
        }
    };

    void cutter::cut_key(pn532::controller &controller, identity id) {
        auto token = find_card(controller);

        auto root_keypair = ka::key_pair();
        root_keypair.generate_from_pwhash("test");
        // generate root key
        if (!token.unlock_root()) {
            ESP_LOGE("KTR", "Error unlocking tag, wrong root key? This is supposed to work only with new cards.");
            return;
        }

        token.setup_mad(id);
        token.setup_root(root_keypair.derive_token_root_key(token.tag().get_card_uid()));
        // Create gate for programmer so we can auth that the key is ours
    }

    void cutter::configure_key_for_gate(pn532::controller &controller, gate g) {

    }
}
