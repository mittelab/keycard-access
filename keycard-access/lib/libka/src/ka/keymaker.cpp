//
// Created by spak on 6/14/23.
//

#include <ka/console.hpp>
#include <ka/keymaker.hpp>
#include <mlab/strutils.hpp>

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