//
// Created by spak on 6/14/23.
//

#include <ka/console.hpp>
#include <ka/keymaker.hpp>
#include <mlab/strutils.hpp>
#include <esp_log.h>

#define TAG "KEYM"

namespace ka {

    using namespace ka::cmd_literals;

    const char *to_string(gate_status gs) {
        switch (gs)  {
            case gate_status::initialized:
                return "initialized";
            case gate_status::configured:
                return "configured";
            case gate_status::deleted:
                return "deleted";
            default:
                return "unknown";
        }
    }


    keymaker::keymaker(std::shared_ptr<nvs::partition> const &partition, std::shared_ptr<pn532::controller> ctrl)
            : device{partition}, _ctrl{std::move(ctrl)} {}

    keymaker::keymaker(key_pair kp)
            : device{kp} {}

    class keymaker::gate_channel {
        std::unique_ptr<pn532::p2p::pn532_target> _raw_target = {};
        std::unique_ptr<p2p::secure_target> _sec_target = {};
        std::unique_ptr<p2p::remote_gate_base> _remote_gate = {};
        unsigned _remote_proto_version = std::numeric_limits<unsigned>::max();
        unsigned _active_proto_version = std::numeric_limits<unsigned>::max();
    public:
        gate_channel() = default;

        explicit gate_channel(pn532::controller &ctrl) {
            _raw_target = std::make_unique<pn532::p2p::pn532_target>(ctrl);
        }

        gate_channel(gate_channel &&) noexcept = default;
        gate_channel &operator=(gate_channel &&) noexcept = default;

        ~gate_channel() {
            if (_remote_gate != nullptr) {
                _remote_gate->bye();
            }
        }

        [[nodiscard]] p2p::r<> connect(key_pair const &kp) {
            if (_raw_target == nullptr) {
                return p2p::error::invalid;
            }
            static constexpr auto nbytes = std::min(raw_pub_key::array_size, pn532::nfcid_3t::array_size);
            pn532::nfcid_3t nfcid{};
            std::copy_n(std::begin(kp.raw_pk()), nbytes, std::begin(nfcid));
            if (const auto r_init = _raw_target->init_as_dep_target(nfcid); r_init) {
                _sec_target = std::make_unique<p2p::secure_target>(*_raw_target, kp);
                if (const auto r_hshake = _sec_target->handshake(); r_hshake) {
                    // Try build a remote_channel
                    _remote_gate = std::make_unique<p2p::remote_gate_base>(*_sec_target);
                    if (const auto r_hello = _remote_gate->hello(); r_hello) {
                        _remote_proto_version = r_hello->proto_version;
                        switch (_remote_proto_version) {
                            case 0:
                                _remote_gate = std::make_unique<p2p::v0::remote_gate>(*_sec_target);
                                break;
                            default:
                                ESP_LOGW(TAG, "Unsupported gate protocol version %u.", _remote_proto_version);
                                return mlab::result_success;
                        }
                        _active_proto_version = _remote_proto_version;
                        ESP_LOGI(TAG, "Connected over gate protocol %u.", _active_proto_version);
                        return mlab::result_success;
                    } else {
                        ESP_LOGE(TAG, "Could not say hi to the gate.");
                        _remote_gate->bye();
                        _remote_gate = nullptr;
                        _sec_target = nullptr;
                        return r_hello.error();
                    }
                } else {
                    // Delete
                    _sec_target = nullptr;
                    return p2p::channel_error_to_p2p_error(r_hshake.error());
                }
            } else {
                return p2p::channel_error_to_p2p_error(r_init.error());
            }
        }

        [[nodiscard]] explicit operator bool() const {
            return _raw_target != nullptr and _sec_target != nullptr and _remote_gate != nullptr;
        }

        [[nodiscard]] unsigned active_proto_version() const {
            return _active_proto_version;
        }


        [[nodiscard]] unsigned remote_proto_version() const {
            return _remote_proto_version;
        }

        [[nodiscard]] p2p::remote_gate_base &remote_gate() {
            return *_remote_gate;
        }

        [[nodiscard]] p2p::remote_gate_base const &remote_gate() const {
            return *_remote_gate;
        }

        template <p2p::remote_gate_protocol Proto = p2p::remote_gate_base>
        [[nodiscard]] Proto const &remote_gate() const {
            if (not *this) {
                ESP_LOGE(TAG, "You should check that the channel is open first.");
                std::abort();
            }
            if constexpr (std::is_same_v<Proto, p2p::remote_gate_base>) {
                return *_remote_gate;
            } else if (auto *prg = dynamic_cast<Proto *>(_remote_gate.get()); prg != nullptr) {
                return *prg;
            } else {
                ESP_LOGE(TAG, "You should make sure this version of the protocol is supported!");
                std::abort();
            }
        }

        template <p2p::remote_gate_protocol Proto = p2p::remote_gate_base>
        [[nodiscard]] Proto &remote_gate() {
            return const_cast<Proto &>(static_cast<gate_channel const *>(this)->remote_gate<Proto>());
        }

    };

    [[nodiscard]] p2p::r<keymaker::gate_channel> keymaker::open_gate_channel() {
        if (not _ctrl) {
            ESP_LOGE(TAG, "Unable to communicate without a PN532 connected.");
            std::abort();
        }
        gate_channel chn{*_ctrl};
        if (const auto r = chn.connect(keys()); r) {
            return std::move(chn);
        } else {
            return r.error();
        }
    }

    gate_id keymaker::register_gate(std::string notes) {
        const gate_id id{_gates.size()};
        _gates.push_back(gate_data{id, std::move(notes), ka::gate_status::initialized, {}, {}});
        return id;
    }

    gate_data const *keymaker::operator[](gate_id id) const {
        const auto i = std::uint32_t(id);
        if (i < gates().size()) {
            return &gates()[i];
        }
        return nullptr;
    }

    void keymaker::set_gate_notes(gate_id id, std::string notes) {
        if (auto const *gd = (*this)[id]; gd != nullptr) {
            // Const-casting so we don't have to repeat the operator[] code.
            const_cast<gate_data *>(gd)->notes = std::move(notes);
        }
    }

    gate_status keymaker::get_gate_status(gate_id id) const {
        if (const auto *gd = (*this)[id]; gd != nullptr) {
            return gd->status;
        }
        return gate_status::unknown;
    }

    gate_info keymaker::get_gate_info(gate_id id) const {
        if (const auto *gd = (*this)[id]; gd != nullptr) {
            return gate_info{gd->id, gd->status, gd->notes, gd->gate_pub_key};
        }
        return gate_info{id, gate_status::unknown, {}, {}};
    }

    namespace cmd {
        template <>
        struct parser<gate_info> {
            [[nodiscard]] static std::string to_string(gate_info const &gi) {
                if (gi.status == gate_status::configured) {
                    return mlab::concatenate({"Gate ", std::to_string(std::uint32_t{gi.id}), "\n",
                                              "Configured, PK ", mlab::data_to_hex_string(gi.public_key.raw_pk()), "\n",
                                              "Notes: ", gi.notes.empty() ? "n/a" : gi.notes});
                } else {
                    return mlab::concatenate({"Gate ", std::to_string(std::uint32_t{gi.id}), "\n",
                                              "Status ", ka::to_string(gi.status),
                                              ".\nNotes: ", gi.notes.empty() ? "n/a" : gi.notes});
                }
            }
        };
        template <>
        struct parser<gate_status> {
            [[nodiscard]] static std::string to_string(gate_status gs) {
                return ka::to_string(gs);
            }
        };
        template <>
        struct parser<gate_id> {
            [[nodiscard]] static std::string to_string(gate_id gid) {
                return parser<std::uint32_t>::to_string(std::uint32_t{gid});
            }
            [[nodiscard]] static ka::cmd::r<gate_id> parse(std::string_view s) {
                if (const auto r = parser<std::uint32_t>::parse(s); r) {
                    return gate_id{*r};
                } else {
                    return r.error();
                }
            }
        };
    }// namespace cmd

    void keymaker::print_gates() const {
        for (std::size_t i = 0; i < gates().size(); ++i) {
            auto const &g = gates()[i];
            std::printf("%2d. Gate %lu (%s)", i + 1, std::uint32_t{g.id}, to_string(g.status));
            if (g.status == gate_status::configured) {
                auto s = mlab::data_to_hex_string(g.gate_pub_key.raw_pk());
                std::printf(" PK: %s", s.c_str());
            }
            std::printf("\n");
        }
    }

    void keymaker::register_commands(ka::cmd::shell &sh) {
        device::register_commands(sh);
        sh.register_command("gate-register", *this, &keymaker::register_gate, {{"notes", {}, ""}});
        sh.register_command("gate-get-info", *this, &keymaker::get_gate_info, {{"gate-id", "gid"}});
        sh.register_command("gate-set-notes", *this, &keymaker::set_gate_notes, {{"gate-id", "gid"}, {"notes"}});
        sh.register_command("gate-get-status", *this, &keymaker::get_gate_status, {{"gate-id", "gid"}});
        sh.register_command("gate-list", *this, &keymaker::print_gates, {});
    }

}// namespace ka