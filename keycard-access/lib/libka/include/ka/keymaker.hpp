//
// Created by spak on 6/14/23.
//

#ifndef KEYCARD_ACCESS_KEYMAKER_HPP
#define KEYCARD_ACCESS_KEYMAKER_HPP

#include <ka/device.hpp>
#include <ka/gate.hpp>
#include <ka/key_pair.hpp>

namespace ka {
    namespace cmd {
        class shell;
    }

    struct gate_data {
        gate_id id = {};
        std::string notes = {};
        std::optional<gate_credentials> credentials = std::nullopt;
    };

    constexpr std::strong_ordering operator<=>(gate_data const &gd, gate_id gid);
    constexpr std::strong_ordering operator<=>(gate_id gid, gate_data const &gd);

    /**
     * Only used for commands
     */
    struct gate_info {
        gate_id id = {};
        std::string_view notes = {};
        std::optional<pub_key> public_key = std::nullopt;

        [[nodiscard]] inline bool is_configured() const { return public_key != std::nullopt; }
    };

    class keymaker : public device {
        std::vector<gate_data> _gates;

    public:
        using device::keys;

        [[nodiscard]] gate_data const *operator[](gate_id id) const;

        gate_id register_gate(std::string notes = "");
        void set_gate_notes(gate_id id, std::string notes);
        [[nodiscard]] bool is_gate_registered(gate_id id) const;
        [[nodiscard]] bool is_gate_configured(gate_id id) const;
        [[nodiscard]] std::optional<gate_info> get_gate_info(gate_id id) const;
        void print_gates() const;

        [[nodiscard]] inline std::vector<gate_data> const &gates() const;


        [[deprecated]] [[nodiscard]] std::vector<gate_config> gate_configs() const {
            std::vector<gate_config> cfgs;
            cfgs.reserve(_gates.size());
            for (std::size_t i = 0; i < _gates.size(); ++i) {
                if (_gates[i].credentials) {
                    gate_config cfg;
                    static_cast<gate_credentials &>(cfg) = *_gates[i].credentials;
                    cfg.id = gate_id{i};
                    cfgs.emplace_back(cfg);
                }
            }
            return cfgs;
        }

        [[deprecated]] [[nodiscard]] gate_id allocate_gate_id() { return gate_id{_gates.size()}; }

        [[deprecated]] void save_gate(gate_config cfg) {
            if (cfg.id == _gates.size()) {
                _gates.emplace_back(gate_data{cfg.id, {}, cfg});
            } else {
                ESP_LOGE("KA", "Invalid gate.");
            }
        }

        void register_commands(ka::cmd::shell &sh) override;
    };

}// namespace ka


namespace ka {
    std::vector<gate_data> const &keymaker::gates() const {
        return _gates;
    }

    constexpr std::strong_ordering operator<=>(gate_data const &gd, gate_id gid) {
        return gd.id <=> gid;
    }
    constexpr std::strong_ordering operator<=>(gate_id gid, gate_data const &gd) {
        return gid <=> gd.id;
    }
}// namespace ka

#endif//KEYCARD_ACCESS_KEYMAKER_HPP
