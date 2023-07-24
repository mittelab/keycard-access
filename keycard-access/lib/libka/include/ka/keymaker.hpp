//
// Created by spak on 6/14/23.
//

#ifndef KEYCARD_ACCESS_KEYMAKER_HPP
#define KEYCARD_ACCESS_KEYMAKER_HPP

#include <hal/gpio_types.h>
#include <ka/device.hpp>
#include <ka/gate.hpp>
#include <ka/key_pair.hpp>
#include <ka/p2p_ops.hpp>

namespace ka {
    struct gpio_responder_config;

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

    static constexpr std::uint8_t rpc_p2p_bit = 1 << 7;

    enum struct rpc_p2p_error : std::uint8_t {
        rpc_parsing_error = static_cast<std::uint8_t>(rpc::error::parsing_error),
        rpc_unknown_command = static_cast<std::uint8_t>(rpc::error::unknown_command),
        rpc_mismatching_signature = static_cast<std::uint8_t>(rpc::error::mismatching_signature),
        rpc_transport_error = static_cast<std::uint8_t>(rpc::error::transport_error),
        rpc_channel_error = static_cast<std::uint8_t>(rpc::error::channel_error),
        rpc_invalid_argument = static_cast<std::uint8_t>(rpc::error::invalid_argument),
        p2p_unauthorized = rpc_p2p_bit | static_cast<std::uint8_t>(p2p::error::unauthorized),
        p2p_invalid_argument = rpc_p2p_bit | static_cast<std::uint8_t>(p2p::error::invalid_argument),
        p2p_invalid_operation = rpc_p2p_bit | static_cast<std::uint8_t>(p2p::error::invalid_operation),
    };

    [[nodiscard]] const char *to_string(rpc_p2p_error e);

    [[nodiscard]] constexpr rpc_p2p_error cast_error(rpc::error e);
    [[nodiscard]] constexpr rpc_p2p_error cast_error(p2p::error e);

    template <class... Args>
    using rpc_p2p_r = mlab::result<rpc_p2p_error, Args...>;

    template <class... Args>
    [[nodiscard]] rpc_p2p_r<Args...> cast_result(rpc::r<Args...> r);

    template <class... Args>
    [[nodiscard]] rpc_p2p_r<Args...> cast_result(p2p::r<Args...> r);

    class keymaker : public device {
        std::shared_ptr<pn532::controller> _ctrl;
        std::shared_ptr<nvs::namespc> _gate_ns;
        std::vector<keymaker_gate_data> _gates;

        class gate_channel;
        class card_channel;

        [[nodiscard]] rpc_p2p_r<gate_channel> open_gate_channel() const;
        [[nodiscard]] desfire::result<card_channel> open_card_channel() const;

        [[nodiscard]] rpc_p2p_r<> configure_gate_internal(keymaker_gate_data &gd);

        /**
         * Prints a message with the gate id and checks whether it's registered to us.
         * @return The gate id and a boolean expressing whether the gate is ours.
         * @todo Add a boolean that fail if not ours
         */
        [[nodiscard]] rpc_p2p_r<gate_id, bool> identify_gate(p2p::remote_gate &rg) const;

        nvs::r<> save_gate(keymaker_gate_data const &gd);

        void restore_gates();
        void turn_rf_off();

    public:
        /**
         * Constructs a device loading all data but the key pair @p kp from the NVS partition. All changes will be persisted.
         */
        explicit keymaker(nvs::partition &partition, device_keypair_storage kp_storage, key_pair kp, std::shared_ptr<pn532::controller> ctrl);


        /**
         * Construct a keymaker the given key pair. Testing purposes, changes will not be persisted
         * and updates are not available on the device.
         */
        explicit keymaker(key_pair kp);

        rpc_p2p_r<gate_id> gate_add(std::string notes = "", bool configure = false);
        rpc_p2p_r<> gate_configure(gate_id id, bool force = false);
        rpc_p2p_r<> gate_remove(gate_id id, bool force = false);
        [[nodiscard]] rpc_p2p_r<p2p::gate_update_config> gate_get_update_config() const;
        [[nodiscard]] rpc_p2p_r<p2p::gate_wifi_status> gate_get_wifi_status() const;
        rpc_p2p_r<> gate_set_update_config(std::string_view update_channel = "", bool automatic_updates = true);
        rpc_p2p_r<bool> gate_connect_wifi(std::string_view ssid, std::string_view password);
        void gate_set_notes(gate_id id, std::string notes);
        [[nodiscard]] gate_status gate_get_status(gate_id id) const;
        [[nodiscard]] rpc_p2p_r<keymaker_gate_info> gate_inspect(gate_id id = std::numeric_limits<gate_id>::max()) const;
        [[nodiscard]] std::vector<keymaker_gate_info> gate_list() const;

        [[nodiscard]] r<desfire::any_key> card_recover_root_key(desfire::any_key test_root_key = desfire::any_key{desfire::cipher_type::none}) const;
        r<> card_format(desfire::any_key old_root_key, desfire::any_key new_root_key);
        r<> card_deploy(desfire::any_key old_root_key, std::string_view holder, std::string_view publisher);
        r<> card_enroll_gate(gate_id gid, std::string_view holder, std::string_view publisher);
        r<> card_unenroll_gate(gate_id gid);
        [[nodiscard]] r<bool> card_is_gate_enrolled(gate_id gid) const;
        [[nodiscard]] r<> card_is_deployed() const;
        [[nodiscard]] r<identity> card_get_identity() const;
        [[nodiscard]] r<std::vector<keymaker_gate_info>> card_list_enrolled_gates() const;

        rpc_p2p_r<release_info> gate_update_check();
        [[nodiscard]] rpc_p2p_r<update_status> gate_is_updating() const;
        rpc_p2p_r<release_info> gate_update_now();
        rpc_p2p_r<> gate_update_manually(std::string_view fw_url);
        rpc_p2p_r<> gate_set_backend_url(std::string_view url, std::string_view api_key);
        [[nodiscard]] rpc_p2p_r<std::string> gate_get_backend_url() const;
        [[nodiscard]] rpc_p2p_r<gpio_responder_config> gate_get_gpio_config() const;
        rpc_p2p_r<> gate_set_gpio_config(gpio_num_t gpio, bool level, std::chrono::milliseconds hold_time);

        void register_commands(ka::cmd::shell &sh) override;
    };
}// namespace ka

namespace ka {
    constexpr rpc_p2p_error cast_error(rpc::error e) {
        return static_cast<rpc_p2p_error>(e);
    }

    constexpr rpc_p2p_error cast_error(p2p::error e) {
        return static_cast<rpc_p2p_error>(static_cast<std::uint8_t>(e) | rpc_p2p_bit);
    }

    template <class... Args>
    rpc_p2p_r<Args...> cast_result(rpc::r<Args...> r) {
        if (r) {
            return std::move(*r);
        } else {
            return cast_error(r.error());
        }
    }

    template <class... Args>
    rpc_p2p_r<Args...> cast_result(p2p::r<Args...> r) {
        if (r) {
            return std::move(*r);
        } else {
            return cast_error(r.error());
        }
    }
}// namespace ka

namespace mlab {
    bin_data &operator<<(bin_data &bd, ka::keymaker_gate_data const &gd);
    bin_stream &operator>>(bin_stream &s, ka::keymaker_gate_data &gd);
}// namespace mlab

#endif//KEYCARD_ACCESS_KEYMAKER_HPP
