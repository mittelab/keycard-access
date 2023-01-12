//
// Created by spak on 10/1/22.
//

#ifndef KEYCARDACCESS_GATE_HPP
#define KEYCARDACCESS_GATE_HPP

#include <ka/data.hpp>
#include <cstdint>
#include <desfire/data.hpp>
#include <ka/key_pair.hpp>

namespace pn532 {
    class controller;
}

namespace ka {
    namespace nvs {
        class partition;
    }

    class member_token;

    class gate {
    public:
        /**
         * @addtogroup Conversion between Gate ID and Desfire App
         * According to AN10787 §3.10 describing the Mifare application directory, on Desfire cards
         * we lock the first nibble of the app id to `F`, then we apply the functional cluster code as
         * per ANNEX C, which in case of access control is `0x51---0x54`. The remaining nibbles are free.
         * Thus we obtain 0x3fff possible gates (which we will never reach because of memory, but ok).
         * @{
         */
        static constexpr std::uint32_t gate_aid_range_begin = 0xf51000;
        static constexpr std::uint32_t gate_aid_range_end = 0xf55000;
        /**
         * @}
         */
        static constexpr std::uint32_t max_gate_id = gate_aid_range_end - gate_aid_range_begin;

        [[nodiscard]] inline static constexpr desfire::app_id id_to_app_id(gate_id id);
        [[nodiscard]] inline static constexpr gate_id app_id_to_id(desfire::app_id id);
        [[nodiscard]] inline static constexpr bool is_gate_app(desfire::app_id id);

        gate() = default;
        gate(gate const &) = delete;
        gate(gate &&) = default;
        gate &operator=(gate const &) = delete;
        gate &operator=(gate &&) = default;

        [[nodiscard]] inline bool is_configured() const;
        [[nodiscard]] inline key_pair keys() const;
        [[nodiscard]] inline pub_key programmer_pub_key() const;
        [[nodiscard]] inline std::string description() const;
        [[nodiscard]] inline gate_id id() const;
        [[nodiscard]] inline gate_context_data context_data() const;

        void configure(gate_id id, std::string desc, pub_key prog_pub_key);

        void store(nvs::partition &partition) const;
        void generate();
        [[nodiscard]] bool load(nvs::partition &partition);
        static void clear(nvs::partition &partition);
        [[nodiscard]] static gate load_or_generate(nvs::partition &partition);
        [[nodiscard]] static gate load_or_generate();

        [[noreturn]] void loop(pn532::controller &controller);
        void interact_with_token(member_token &token, token_id  const &nfc_id);

    private:
        gate_id _id = std::numeric_limits<gate_id>::max();
        std::string _desc;
        key_pair _kp;
        pub_key _prog_pk;
        gate_context_data _ctx{};
    };
}// namespace ka

namespace ka {
    bool gate::is_configured() const {
        return _id != std::numeric_limits<gate_id>::max();
    }
    key_pair gate::keys() const {
        return _kp;
    }
    pub_key gate::programmer_pub_key() const {
        return _prog_pk;
    }
    std::string gate::description() const {
        return _desc;
    }
    gate_id gate::id() const {
        return _id;
    }

    gate_context_data gate::context_data() const {
        return _ctx;
    }

    constexpr desfire::app_id gate::id_to_app_id(gate_id id) {
        const std::uint32_t app_id_uint = id + gate_aid_range_begin;
        return {std::uint8_t((app_id_uint >> 16) & 0xff),
                std::uint8_t((app_id_uint >> 8) & 0xff),
                std::uint8_t(app_id_uint & 0xff)};
    }

    constexpr gate_id gate::app_id_to_id(desfire::app_id id) {
        const std::uint32_t app_id_uint =
                (std::uint32_t(id[2]) << 16) |
                (std::uint32_t(id[1]) << 8) |
                std::uint32_t(id[0]);
        return app_id_uint - gate_aid_range_begin;
    }

    constexpr bool gate::is_gate_app(desfire::app_id id) {
        const std::uint32_t app_id_uint =
                (std::uint32_t(id[2]) << 16) |
                (std::uint32_t(id[1]) << 8) |
                std::uint32_t(id[0]);
        return app_id_uint >= gate_aid_range_begin and app_id_uint < gate_aid_range_end;
    }
}// namespace ka

#endif//KEYCARDACCESS_GATE_HPP
