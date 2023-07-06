//
// Created by spak on 6/14/23.
//

#include <ka/console.hpp>
#include <ka/keymaker.hpp>
#include <mlab/strutils.hpp>

namespace ka {

    using namespace ka::cmd_literals;

    gate_id keymaker::register_gate(std::string notes) {
        gate_id max_id{0};
        for (auto const &gd : gates()) {
            max_id = std::max(max_id, gd.id);
        }
        // Increment by one
        auto const &gd = _gates.emplace_back(gate_data{gate_id{std::uint32_t{max_id} + 1}, std::move(notes), std::nullopt});
        return gd.id;
    }

    gate_data const *keymaker::operator[](gate_id id) const {
        auto it = std::lower_bound(std::begin(gates()), std::end(gates()), id);
        if (it == std::end(gates()) or it->id != id) {
            return nullptr;
        }
        return &*it;
    }

    void keymaker::set_gate_notes(gate_id id, std::string notes) {
        if (auto const *gd = (*this)[id]; gd != nullptr) {
            // Const-casting so we don't have to repeat the operator[] code.
            const_cast<gate_data *>(gd)->notes = std::move(notes);
        }
    }

    bool keymaker::is_gate_registered(gate_id id) const {
        return (*this)[id] != nullptr;
    }

    bool keymaker::is_gate_configured(gate_id id) const {
        if (const auto *gd = (*this)[id]; gd != nullptr) {
            return gd->credentials != std::nullopt;
        }
        return false;
    }

    std::optional<registerd_gate_info> keymaker::get_gate_info(gate_id id) const {
        if (const auto *gd = (*this)[id]; gd != nullptr) {
            return registerd_gate_info{gd->id, gd->notes, gd->credentials != std::nullopt ? std::optional<pub_key>{gd->credentials->gate_pub_key} : std::nullopt};
        }
        return std::nullopt;
    }

    namespace cmd {
        template <>
        struct parser<registerd_gate_info> {
            [[nodiscard]] static std::string to_string(registerd_gate_info const &gi) {
                if (gi.is_configured()) {
                    return mlab::concatenate({"Gate ", std::to_string(std::uint32_t{gi.id}), "\n",
                                              "Configured, public key ", mlab::data_to_hex_string(gi.public_key->raw_pk()), "\n",
                                              "Notes: ", gi.notes.empty() ? "n/a" : gi.notes});
                } else {
                    return mlab::concatenate({"Gate ", std::to_string(std::uint32_t{gi.id}), "\n",
                                              "Not configured.\nNotes: ", gi.notes.empty() ? "n/a" : gi.notes});
                }
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
            std::printf("%2d. Gate %lu (%s)", i + 1, std::uint32_t{g.id}, g.credentials ? "configured" : "not configured");
            if (g.credentials) {
                auto s = mlab::data_to_hex_string(g.credentials->gate_pub_key.raw_pk());
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
        sh.register_command("gate-is-registered", *this, &keymaker::is_gate_registered, {{"gate-id", "gid"}});
        sh.register_command("gate-is-configured", *this, &keymaker::is_gate_configured, {{"gate-id", "gid"}});
        sh.register_command("gate-list", *this, &keymaker::print_gates, {});
    }

}// namespace ka