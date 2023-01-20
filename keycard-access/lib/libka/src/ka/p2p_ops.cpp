//
// Created by spak on 1/20/23.
//

#include <desfire/esp32/utils.hpp>
#include <ka/gate.hpp>
#include <ka/p2p_ops.hpp>
#include <ka/secure_p2p.hpp>
#include <pn532/controller.hpp>
#include <pn532/p2p.hpp>
#include <ka/desfire_fs.hpp>


namespace ka::p2p {
    namespace bits {
        static constexpr std::uint8_t command_code_configure = 0xcf;
    }

    namespace {
        [[nodiscard]] std::array<std::uint8_t, 10> fabricate_nfcid(gate const &g) {
            return {
                    std::uint8_t(g.id() & 0xff),
                    std::uint8_t((g.id() >> 8) & 0xff),
                    std::uint8_t((g.id() >> 16) & 0xff),
                    std::uint8_t((g.id() >> 24) & 0xff),
                    0x6a, 0x7e, 0xde, 0xad, 0xbe, 0xef /* L33T garbage */
            };
        }

        pn532::p2p::result<> configure_gate_internal(gate &g, secure_target &comm) {
            TRY(comm.handshake());
            ESP_LOGI("KA", "Comm opened, peer's public key:");
            ESP_LOG_BUFFER_HEX_LEVEL("KA", comm.peer_pub_key().data(), comm.peer_pub_key().size(), ESP_LOG_INFO);

            TRY_RESULT(comm.receive(1s)) {
                gate_id new_id = g.id();
                mlab::bin_stream s{*r};
                if (s.pop() != bits::command_code_configure) {
                    s.set_bad();
                }
                s >> mlab::lsb32 >> new_id;
                std::string new_desc = mlab::data_to_string(s.peek());
                if (s.bad()) {
                    ESP_LOGE("KA", "Invalid configure command received.");
                    return pn532::channel::error::comm_malformed;
                }

                // Finally:
                g.configure(new_id, std::move(new_desc), pub_key{comm.peer_pub_key()});
                TRY(comm.send(mlab::data_from_string("ok"), 1s))
            }
            return mlab::result_success;
        }
    }

    void configure_gate(pn532::controller &ctrl, gate &g) {
        pn532::p2p::pn532_target raw_comm{ctrl};
        while (not g.is_configured()) {
            // Make sure you get fresh new keys
            g.regenerate_keys();
            desfire::esp32::suppress_log suppress{ESP_LOG_ERROR, {PN532_TAG}};
            while (not raw_comm.init_as_dep_target(fabricate_nfcid(g))) {
                suppress.restore();
                secure_target comm{raw_comm, g.keys()};
                if (configure_gate_internal(g, comm)) {
                    return;
                }
            }
        }
    }

}