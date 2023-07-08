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

    enum struct gate_status {
        unknown,
        initialized,
        configured,
        deleted
    };

    [[nodiscard]] const char *to_string(gate_status gs);

    struct gate_data {
        gate_id id = {};
        std::string notes = {};
        gate_status status = gate_status::unknown;
        pub_key gate_pub_key = {};
        gate_base_key app_base_key = {};
    };

    /**
     * Only used for commands
     */
    struct gate_info {
        gate_id id = {};
        gate_status  status = gate_status::unknown;
        std::string_view notes = {};
        pub_key public_key = {};
    };

    class keymaker : public device {
        std::shared_ptr<pn532::controller> _ctrl;
        std::vector<gate_data> _gates;

        class gate_channel;

        [[nodiscard]] p2p::r<gate_channel> open_gate_channel();
    public:
        /**
         * Construct a device loading it from the NVS partition. All changes will be persisted.
         */
        explicit keymaker(std::shared_ptr<nvs::partition> const &partition, std::shared_ptr<pn532::controller> ctrl);

        /**
         * Construct a keymaker the given key pair. Testing purposes, changes will not be persisted
         * and updates are not available on the device.
         */
        explicit keymaker(key_pair kp);


        /**
         * @todo Consider removing this. Might be hard, lots of usages in member_token
         */
        using device::keys;

        [[nodiscard]] gate_data const *operator[](gate_id id) const;

        gate_id register_gate(std::string notes = "");
        void set_gate_notes(gate_id id, std::string notes);
        [[nodiscard]] gate_status get_gate_status(gate_id id) const;
        [[nodiscard]] gate_info get_gate_info(gate_id id) const;
        void print_gates() const;

        [[nodiscard]] inline std::vector<gate_data> const &gates() const;


        [[deprecated]] [[nodiscard]] std::vector<gate_config> gate_configs() const {
            std::vector<gate_config> cfgs;
            cfgs.reserve(_gates.size());
            for (auto const &gd : _gates) {
                if (gd.status == gate_status::configured) {
                    cfgs.emplace_back(gate_config{gate_credentials{gd.gate_pub_key, gd.app_base_key}, gd.id});
                }
            }
            return cfgs;
        }

        void register_commands(ka::cmd::shell &sh) override;
    };

}// namespace ka


namespace ka {
    std::vector<gate_data> const &keymaker::gates() const {
        return _gates;
    }
}// namespace ka

#endif//KEYCARD_ACCESS_KEYMAKER_HPP
