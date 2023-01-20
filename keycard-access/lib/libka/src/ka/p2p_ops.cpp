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
        static constexpr auto command_ok = "ok";
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
                TRY(comm.send(mlab::data_from_string(bits::command_ok), 1s))
            }
            return mlab::result_success;
        }

        class configure_gate_responder final : public pn532::scanner_responder {
            keymaker &_km;
            std::string _desc;
            bool _success;
        public:
            configure_gate_responder(keymaker &km, std::string desc) : _km{km}, _desc{std::move(desc)}, _success{false} {}

            [[nodiscard]] inline bool success() const { return _success; }

            void get_scan_target_types(pn532::scanner &, std::vector<pn532::target_type> &targets) const override {
                targets = {pn532::target_type::dep_passive_424kbps, pn532::target_type::dep_passive_212kbps, pn532::target_type::dep_passive_106kbps};
            }


            pn532::p2p::result<> interact_internal(secure_initiator &comm) {
                TRY(comm.handshake());
                ESP_LOGI("KA", "Comm opened, peer's public key:");
                ESP_LOG_BUFFER_HEX_LEVEL("KA", comm.peer_pub_key().data(), comm.peer_pub_key().size(), ESP_LOG_INFO);

                /**
                 * @todo Return the ID if needed.
                 */
                const auto gid = _km.allocate_gate_id();
                mlab::bin_data msg{mlab::prealloc(6 + _desc.size())};
                msg << bits::command_code_configure << mlab::lsb32 << gid << mlab::view_from_string(_desc);
                TRY_RESULT(comm.communicate(msg, 1s)) {
                    const std::string response = mlab::data_to_string(*r);
                    if (response != bits::command_ok) {
                        ESP_LOGE("KA", "Invalid configure response received.");
                        return pn532::channel::error::comm_malformed;
                    }
                }

                _km.register_gate(gid, comm.peer_pub_key(), _desc);
                return mlab::result_success;
            }

            pn532::post_interaction interact(pn532::scanner &scanner, const pn532::scanned_target &target) override {
                pn532::p2p::pn532_initiator raw_comm{scanner.ctrl(), target.index};
                secure_initiator comm{raw_comm, _km.keys()};
                if (interact_internal(comm)) {
                    _success = true;
                }
                return pn532::post_interaction::abort;
            }
        };

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

    bool configure_gate(pn532::controller &ctrl, keymaker &km, std::string gate_description) {
        configure_gate_responder responder{km, std::move(gate_description)};
        pn532::scanner scanner{ctrl};
        scanner.loop(responder, false);
        return responder.success();
    }

}