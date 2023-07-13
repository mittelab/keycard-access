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

    struct keymaker_gate_extra_data {
        gate_status status = gate_status::unknown;
        std::string notes = {};
    };

    struct keymaker_gate_data : gate_sec_info, keymaker_gate_extra_data {
        keymaker_gate_data() = default;

        keymaker_gate_data(gate_id id_, pub_key pk_, gate_base_key bk_, gate_status s_, std::string notes_)
            : gate_sec_info{id_, pk_, bk_}, keymaker_gate_extra_data{s_, std::move(notes_)} {}

        [[nodiscard]] nvs::r<> save_to(nvs::namespc &ns) const;
        [[nodiscard]] static std::string get_nvs_key(gate_id gid);
        [[nodiscard]] static nvs::r<keymaker_gate_data> load_from(nvs::const_namespc const &ns, gate_id gid);
        [[nodiscard]] static std::vector<keymaker_gate_data> load_from(nvs::const_namespc const &ns);
    };

    struct keymaker_gate_info : gate_pub_info, keymaker_gate_extra_data {
        keymaker_gate_info(gate_id id_, pub_key pk_, gate_status s_, std::string notes_)
            : gate_pub_info{id_, pk_}, keymaker_gate_extra_data{s_, std::move(notes_)} {}

        keymaker_gate_info(keymaker_gate_data const &gd) : gate_pub_info{gd}, keymaker_gate_extra_data{gd} {}
    };

    class keymaker : public device {
        std::shared_ptr<pn532::controller> _ctrl;
        std::vector<keymaker_gate_data> _gates;
        std::shared_ptr<nvs::namespc> _gate_ns = nullptr;

        class gate_channel;
        class card_channel;

        [[nodiscard]] p2p::r<gate_channel> open_gate_channel() const;
        [[nodiscard]] desfire::result<card_channel> open_card_channel() const;

        [[nodiscard]] p2p::r<> configure_gate_internal(keymaker_gate_data &gd);

        [[nodiscard]] p2p::r<gate_id, bool> check_if_detected_gate_is_ours(p2p::v0::remote_gate &rg) const;

        nvs::r<> save_gate(keymaker_gate_data const &gd);

        [[nodiscard]] desfire::result<desfire::any_key> recover_card_root_key_internal(desfire::any_key hint = desfire::key<desfire::cipher_type::des>{}) const;
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

        gate_id gate_add(std::string notes = "", bool configure = false);
        bool gate_configure(gate_id id, bool force = false);
        bool gate_remove(gate_id id, bool force = false);
        std::optional<p2p::v0::update_config> gate_get_update_config();
        std::optional<p2p::v0::wifi_status> gate_get_wifi_status();
        bool gate_set_update_config(std::string_view update_channel = "", bool automatic_updates = true);
        bool gate_connect_wifi(std::string_view ssid, std::string_view password);
        void gate_set_notes(gate_id id, std::string notes);
        [[nodiscard]] gate_status gate_get_status(gate_id id) const;
        [[nodiscard]] std::optional<keymaker_gate_info> gate_inspect(gate_id id = std::numeric_limits<gate_id>::max()) const;
        [[nodiscard]] std::vector<keymaker_gate_info> gate_list() const;

        [[nodiscard]] std::optional<desfire::any_key> card_recover_root_key() const;
        [[nodiscard]] bool card_format(desfire::any_key old_root_key, desfire::any_key new_root_key) const;

        void register_commands(ka::cmd::shell &sh) override;
    };

}// namespace ka

namespace mlab {
    bin_data &operator<<(bin_data &bd, ka::keymaker_gate_data const &gd);
    bin_stream &operator>>(bin_stream &s, ka::keymaker_gate_data &gd);
}// namespace mlab

#endif//KEYCARD_ACCESS_KEYMAKER_HPP
