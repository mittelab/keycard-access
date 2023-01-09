//
// Created by spak on 10/1/22.
//

#ifndef KEYCARDACCESS_GATE_HPP
#define KEYCARDACCESS_GATE_HPP

#include <ka/data.hpp>
#include <cstdint>
#include <desfire/data.hpp>

namespace ka {

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

        [[nodiscard]] inline gate_id id() const;
        [[nodiscard]] inline desfire::app_id app_id() const;

        [[nodiscard]] inline static constexpr desfire::app_id id_to_app_id(gate_id id);
        [[nodiscard]] inline static constexpr gate_id app_id_to_id(desfire::app_id id);
        [[nodiscard]] inline static constexpr bool is_gate_app(desfire::app_id id);

        inline explicit gate(gate_id id);
        gate(gate const &) = delete;
        gate(gate &&) = default;
        gate &operator=(gate const &) = delete;
        gate &operator=(gate &&) = default;

    private:
        gate_id _id;
    };
}// namespace ka

namespace ka {
    gate::gate(gate_id id) : _id{id} {}

    gate_id gate::id() const {
        return _id;
    }

    desfire::app_id gate::app_id() const {
        return id_to_app_id(id());
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
