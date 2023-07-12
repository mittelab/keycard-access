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

    enum struct gate_status : std::uint8_t {
        unknown = 0,
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

        [[nodiscard]] nvs::r<> save_to(nvs::namespc &ns) const;
        [[nodiscard]] static std::string get_nvs_key(gate_id gid);
        [[nodiscard]] static nvs::r<gate_data> load_from(nvs::const_namespc const &ns, gate_id gid);
        [[nodiscard]] static std::vector<gate_data> load_from(nvs::const_namespc const &ns);
    };

    /**
     * Only used for commands
     */
    struct gate_info {
        gate_id id = {};
        gate_status status = gate_status::unknown;
        std::string_view notes = {};
        pub_key public_key = {};
    };

    class keymaker : public device {
        std::shared_ptr<pn532::controller> _ctrl;
        std::vector<gate_data> _gates;
        std::shared_ptr<nvs::namespc> _gate_ns = nullptr;

        class gate_channel;
        class card_channel;

        [[nodiscard]] p2p::r<gate_channel> open_gate_channel() const;
        [[nodiscard]] pn532::result<card_channel> open_card_channel() const;

        [[nodiscard]] p2p::r<> configure_gate_internal(gate_data &gd);

        [[nodiscard]] p2p::r<gate_id, bool> check_if_detected_gate_is_ours(p2p::v0::remote_gate &rg) const;

        nvs::r<> save_gate(gate_data const &gd);

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

        gate_id register_gate(std::string notes = "", bool configure = false);
        bool configure_gate(gate_id id, bool force = false);
        bool delete_gate(gate_id id, bool force = false);
        std::optional<p2p::v0::update_settings> get_gate_update_settings();
        std::optional<p2p::v0::wifi_status> get_gate_wifi_status();
        bool set_gate_update_settings(std::string_view update_channel = "", bool automatic_updates = true);
        bool connect_gate_wifi(std::string_view ssid, std::string_view password);
        void set_gate_notes(gate_id id, std::string notes);
        [[nodiscard]] gate_status get_gate_status(gate_id id) const;
        [[nodiscard]] std::optional<gate_info> inspect_gate(gate_id id = std::numeric_limits<gate_id>::max()) const;
        void print_gates() const;

        [[nodiscard]] std::optional<desfire::any_key> recover_card_root_key() const;

        [[nodiscard]] inline std::vector<gate_data> const &gates() const;


        void register_commands(ka::cmd::shell &sh) override;
    };

}// namespace ka

namespace mlab {
    bin_data &operator<<(bin_data &bd, ka::gate_data const &gd);
    bin_stream &operator>>(bin_stream &s, ka::gate_data &gd);
}

namespace ka {
    std::vector<gate_data> const &keymaker::gates() const {
        return _gates;
    }
}// namespace ka

#endif//KEYCARD_ACCESS_KEYMAKER_HPP
