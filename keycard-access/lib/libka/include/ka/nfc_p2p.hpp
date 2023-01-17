//
// Created by spak on 1/16/23.
//

#ifndef KEYCARD_ACCESS_NFC_P2P_HPP
#define KEYCARD_ACCESS_NFC_P2P_HPP
#include <pn532/controller.hpp>

namespace ka::nfc {

    using ms = std::chrono::milliseconds;

    template <class ...Args>
    using result = pn532::controller::result<Args...>;

    struct p2p_initiator {
        [[nodiscard]] virtual result<mlab::bin_data> communicate(mlab::bin_data const &data, ms timeout) = 0;
        [[nodiscard]] virtual result<> goodbye() = 0;

        virtual ~p2p_initiator() = default;
    };

    struct p2p_target {
        [[nodiscard]] virtual result<mlab::bin_data> receive(ms timeout) = 0;
        [[nodiscard]] virtual result<> send(mlab::bin_data const &data, ms timeout) = 0;
        virtual ~p2p_target() = default;
    };

    class pn532_initiator : p2p_initiator {
        std::shared_ptr<pn532::controller> _controller;
        std::uint8_t _idx{};
    public:
        pn532_initiator() = default;
        pn532_initiator(std::shared_ptr<pn532::controller> controller, std::uint8_t log_idx);
        pn532_initiator(pn532_initiator const &) = delete;
        pn532_initiator &operator=(pn532_initiator const &) = delete;
        pn532_initiator(pn532_initiator &&) noexcept = default;
        pn532_initiator &operator=(pn532_initiator &&) noexcept = default;

        [[nodiscard]] inline std::uint8_t target_logical_index() const;
        [[nodiscard]] inline pn532::controller &controller();

        [[nodiscard]] result<mlab::bin_data> communicate(mlab::bin_data const &data, ms timeout) override;
        [[nodiscard]] result<> goodbye() override;
    };

    class pn532_target : p2p_target {
        std::shared_ptr<pn532::controller> _controller;
    public:
        static constexpr std::array<std::uint8_t, 10> default_nfcid3 = {0x30, 0xfd, 0xd9, 0x50, 0xdc, 0xaa, 0x69, 0x89, 0x28, 0xe1};

        pn532_target() = default;
        explicit pn532_target(std::shared_ptr<pn532::controller> controller);
        /**
         * This will call @ref pn532::controller::target_init_as_target
         * @param controller
         * @param nfcid_3t
         */
        pn532_target(std::shared_ptr<pn532::controller> controller, std::array<std::uint8_t, 10> nfcid_3t);
        pn532_target(pn532_target const &) = delete;
        pn532_target &operator=(pn532_target const &) = delete;
        pn532_target(pn532_target &&) noexcept = default;
        pn532_target &operator=(pn532_target &&) noexcept = default;

        [[nodiscard]] inline pn532::controller &controller();
        [[nodiscard]] result<mlab::bin_data> receive(ms timeout) override;
        [[nodiscard]] result<> send(mlab::bin_data const &data, ms timeout) override;
    };
}

namespace ka::nfc {
    std::uint8_t pn532_initiator::target_logical_index() const {
        return _idx;
    }

    pn532::controller &pn532_initiator::controller() {
        return *_controller;
    }
    pn532::controller &pn532_target::controller() {
        return *_controller;
    }
}

#endif//KEYCARD_ACCESS_NFC_P2P_HPP
