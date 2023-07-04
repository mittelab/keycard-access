//
// Created by spak on 1/20/23.
//

#include <desfire/esp32/utils.hpp>
#include <ka/desfire_fs.hpp>
#include <ka/gate.hpp>
#include <ka/keymaker.hpp>
#include <ka/p2p_ops.hpp>
#include <ka/secure_p2p.hpp>
#include <mlab/strutils.hpp>
#include <pn532/controller.hpp>
#include <pn532/p2p.hpp>

namespace ka::p2p {
    namespace bits {
        static constexpr std::uint8_t command_code_configure = 0xcf;
        static constexpr std::uint8_t command_hello = 0x00;
        static constexpr std::uint8_t command_bye = 0x01;
    }// namespace bits

    namespace {

        [[nodiscard]] r<> parse_return_byte(std::uint8_t b) {
            switch (b) {
                case 0x00:
                    return mlab::result_success;
                case static_cast<std::uint8_t>(error::unauthorized):
                    return error::unauthorized;
                case static_cast<std::uint8_t>(error::invalid):
                    return error::invalid;
                default:
                    ESP_LOGE("KA", "Unknown result byte %02x", b);
                    [[fallthrough]];
                case static_cast<std::uint8_t>(error::malformed):
                    return error::malformed;
            }
        }

        [[nodiscard]] pn532::nfcid_3t fabricate_nfcid(gate const &g) {
            return {
                    std::uint8_t(g.id() & 0xff),
                    std::uint8_t((g.id() >> 8) & 0xff),
                    std::uint8_t((g.id() >> 16) & 0xff),
                    std::uint8_t((g.id() >> 24) & 0xff),
                    0x6a, 0x7e, 0xde, 0xad, 0xbe, 0xef /* L33T garbage */
            };
        }


        class configure_gate_responder final : public pn532::scanner_responder {
            keymaker &_km;
            std::string const &_desc;
            bool _success;

        public:
            configure_gate_responder(keymaker &km, std::string const &desc) : _km{km}, _desc{desc}, _success{false} {}

            [[nodiscard]] inline bool success() const { return _success; }

            std::vector<pn532::target_type> get_scan_target_types(pn532::scanner &) const override {
                return {pn532::target_type::dep_passive_424kbps, pn532::target_type::dep_passive_212kbps, pn532::target_type::dep_passive_106kbps};
            }

            pn532::post_interaction interact(pn532::scanner &scanner, const pn532::scanned_target &target) override {
                if (configure_gate_in_rf(scanner.ctrl(), target.index, _km, _desc)) {
                    _success = true;
                }
                return pn532::post_interaction::abort;
            }
        };

    }// namespace

    void configure_gate_loop(pn532::controller &ctrl, gate &g) {
        pn532::p2p::pn532_target raw_comm{ctrl};
        while (not g.is_configured()) {
            // Make sure you get fresh new keys
            g.regenerate_keys();
            while (not g.is_configured()) {
                desfire::esp32::suppress_log suppress{ESP_LOG_ERROR, {PN532_TAG}};
                if (raw_comm.init_as_dep_target(fabricate_nfcid(g))) {
                    suppress.restore();
                    if (configure_gate_in_rf(ctrl, g)) {
                        return;
                    }
                }
            }
        }
    }

    bool configure_gate_loop(pn532::controller &ctrl, keymaker &km, std::string const &gate_description) {
        configure_gate_responder responder{km, gate_description};
        pn532::scanner scanner{ctrl};
        scanner.loop(responder, false);
        return responder.success();
    }

    pn532::result<> configure_gate_exchange(gate &g, secure_target &comm) {
        TRY(comm.handshake());
        ESP_LOGI("KA", "Comm opened, peer's public key:");
        ESP_LOG_BUFFER_HEX_LEVEL("KA", comm.peer_pub_key().data(), comm.peer_pub_key().size(), ESP_LOG_INFO);

        TRY_RESULT(comm.receive(1s)) {
            std::uint32_t new_id = g.id();
            mlab::bin_stream s{*r};
            if (s.pop() != bits::command_code_configure) {
                s.set_bad();
            }
            s >> mlab::lsb32 >> new_id;
            std::string new_desc = mlab::data_to_string(s.peek());
            if (s.bad()) {
                ESP_LOGE("KA", "Invalid configure command received.");
                return pn532::channel_error::malformed;
            }

            // Finally:
            g.configure(gate_id{new_id}, std::move(new_desc), pub_key{comm.peer_pub_key()});
            g.log_public_gate_info();
            TRY(comm.send(mlab::bin_data::chain(g.app_base_key()), 1s))
        }
        return mlab::result_success;
    }

    pn532::result<> configure_gate_exchange(keymaker &km, secure_initiator &comm, std::string const &gate_description) {
        TRY(comm.handshake());
        ESP_LOGI("KA", "Comm opened, peer's public key:");
        ESP_LOG_BUFFER_HEX_LEVEL("KA", comm.peer_pub_key().data(), comm.peer_pub_key().size(), ESP_LOG_INFO);

        /**
         * @todo Return the ID if needed.
         */
        const auto gid = km.allocate_gate_id();
        mlab::bin_data msg{mlab::prealloc(6 + gate_description.size())};
        msg << bits::command_code_configure << mlab::lsb32 << std::uint32_t(gid) << mlab::data_view_from_string(gate_description);
        TRY_RESULT(comm.communicate(msg, 1s)) {
            if (r->size() != gate_base_key::array_size) {
                ESP_LOGE("KA", "Invalid configure response received.");
                return pn532::channel_error::malformed;
            }
            gate_base_key base_key{};
            std::copy(std::begin(*r), std::end(*r), std::begin(base_key));
            km.save_gate({{pub_key{comm.peer_pub_key()}, base_key}, gid});
        }

        return mlab::result_success;
    }

    bool configure_gate_in_rf(pn532::controller &ctrl, gate &g) {
        pn532::p2p::pn532_target raw_comm{ctrl};
        secure_target comm{raw_comm, g.keys()};
        return bool(configure_gate_exchange(g, dynamic_cast<secure_target &>(comm)));
    }

    bool configure_gate_in_rf(pn532::controller &ctrl, std::uint8_t logical_index, keymaker &km, std::string const &gate_description) {
        pn532::p2p::pn532_initiator raw_comm{ctrl, logical_index};
        secure_initiator comm{raw_comm, km.keys()};
        return bool(configure_gate_exchange(km, comm, gate_description));
    }

    remote_gate_base::remote_gate_base(secure_initiator &remote_gate) : _remote_gate{remote_gate} {}

    pub_key remote_gate_base::gate_public_key() const {
        return pub_key{remote().peer_pub_key()};
    }

    r<gate_fw_info> remote_gate_base::hello_and_assert_protocol(std::uint8_t proto_version) {
        auto r = remote_gate_base::hello();
        if (r->proto_version != proto_version) {
            ESP_LOGE("KA", "Mismatching protocol version %d", r->proto_version);
            return error::invalid;
        }
        return r;
    }

    r<mlab::bin_data> remote_gate_base::command_response(mlab::bin_data const &command) {
        if (auto r = remote().communicate(command, 5s); r) {
            // Last byte identifies the status code
            if (r->empty()) {
                return error::malformed;
            }
            const auto status_b = r->back();
            r->pop_back();
            if (const auto r_status = parse_return_byte(status_b); r_status) {
                return std::move(*r);
            } else {
                return r_status.error();
            }
        } else {
            return channel_error_to_p2p_error(r.error());
        }
    }

    bool remote_gate_base::assert_stream_healthy(mlab::bin_stream const &s) {
        if (not s.eof()) {
            ESP_LOGW("KA", "Stray %u bytes at the end of the stream.", s.remaining());
            return false;
        } else if (s.bad()) {
            ESP_LOGW("KA", "Malformed or unreadable response.");
            return false;
        }
        return true;
    }

    r<gate_fw_info> remote_gate_base::hello() {
        return command_parse_response<gate_fw_info>(bits::command_hello);
    }

    void remote_gate_base::bye() {
        void(command_parse_response<void>(bits::command_bye));
    }

    namespace v0 {
        enum struct commands : std::uint8_t {
            _reserved1 [[maybe_unused]] = bits::command_hello,///< Reserved, make sure it does not clash
            _reserved2 [[maybe_unused]] = bits::command_bye,  ///< Reserved, make sure it does not clash
            get_update_settings = 0x02,
            set_update_settings = 0x03,
            get_wifi_status = 0x04,
            connect_wifi = 0x05,
            get_registration_info = 0x06,
            register_gate = 0x07,
            reset_gate = 0x08,
        };

        r<registration_info> remote_gate::get_registration_info() {
            return command_parse_response<registration_info>(commands::get_registration_info);
        }

        r<update_settings> remote_gate::get_update_settings() {
            return command_parse_response<update_settings>(commands::get_update_settings);
        }

        r<> remote_gate::set_update_settings(std::string_view update_channel, bool automatic_updates) {
            return command_parse_response<void>(
                    mlab::prealloc{update_channel.size() + 6},
                    commands::set_update_settings,
                    mlab::length_encoded, update_channel,
                    automatic_updates);
        }


        r<wifi_status> remote_gate::get_wifi_status() {
            return command_parse_response<wifi_status>(commands::get_wifi_status);
        }

        r<bool> remote_gate::connect_wifi(std::string_view ssid, std::string_view password) {
            return command_parse_response<bool>(mlab::prealloc{ssid.size() + password.size() + 9},
                                                commands::connect_wifi,
                                                mlab::length_encoded, ssid,
                                                mlab::length_encoded, password);
        }

        r<gate_fw_info> remote_gate::hello() {
            return hello_and_assert_protocol(0);
        }

        r<> remote_gate::register_gate(gate_id requested_id) {
            return command_parse_response<void>(commands::register_gate);
        }

        r<> remote_gate::reset_gate() {
            return command_parse_response<void>(commands::reset_gate);
        }
    }// namespace v0

}// namespace ka::p2p

namespace mlab {
    bin_stream &operator>>(bin_stream &s, ka::p2p::gate_fw_info &fwinfo) {
        s >> fwinfo.semantic_version;
        s >> length_encoded >> fwinfo.commit_info;
        s >> length_encoded >> fwinfo.app_name;
        s >> length_encoded >> fwinfo.platform_code;
        s >> fwinfo.proto_version;
        return s;
    }

    bin_stream &operator>>(bin_stream &s, ka::gate_id &gid) {
        std::uint32_t v{};
        s >> lsb32 >> v;
        if (not s.bad()) {
            gid = ka::gate_id{v};
        }
        return s;
    }

    bin_stream &operator>>(bin_stream &s, ka::raw_pub_key &pk) {
        s >> static_cast<std::array<std::uint8_t, ka::raw_pub_key::array_size> &>(pk);
        return s;
    }

    bin_stream &operator>>(bin_stream &s, ka::p2p::v0::registration_info &rinfo) {
        s >> rinfo.id >> rinfo.km_pk;
        return s;
    }

    bin_stream &operator>>(bin_stream &s, ka::p2p::v0::update_settings &usettings) {
        s >> length_encoded >> usettings.update_channel >> usettings.enable_automatic_update;
        return s;
    }

    bin_stream &operator>>(bin_stream &s, ka::p2p::v0::wifi_status &wfsettings) {
        s >> length_encoded >> wfsettings.ssid >> wfsettings.operational;
        return s;
    }

    bin_stream &operator>>(bin_stream &s, ka::pub_key &pk) {
        ka::raw_pub_key rpk{};
        s >> rpk;
        if (not s.bad()) {
            pk = ka::pub_key{rpk};
        }
        return s;
    }

    bin_data &operator<<(encode_length<bin_data> w, std::string_view s) {
        return w.s << mlab::lsb32 << w.s.size() << mlab::data_from_string(s);
    }

    bin_stream &operator>>(encode_length<bin_stream> w, std::string &str) {
        auto &s = w.s;
        if (s.bad() or s.remaining() < 4) {
            s.set_bad();
            return s;
        }
        std::uint32_t length = 0;
        s >> mlab::lsb32 >> length;
        if (s.bad()) {
            return s;
        }
        if (s.remaining() < length) {
            s.set_bad();
            return s;
        }
        str = mlab::data_to_string(s.read(length));
        return s;
    }

    bin_stream &operator>>(bin_stream &s, semver::version &v) {
        if (s.bad()) {
            return s;
        }
        if (s.remaining() < 5) {
            s.set_bad();
            return s;
        }

        s >> v.major >> v.minor >> v.patch >> v.prerelease_type >> v.prerelease_number;
        return s;
    }
}// namespace mlab