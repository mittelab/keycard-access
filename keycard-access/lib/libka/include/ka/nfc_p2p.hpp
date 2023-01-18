//
// Created by spak on 1/16/23.
//

#ifndef KEYCARD_ACCESS_NFC_P2P_HPP
#define KEYCARD_ACCESS_NFC_P2P_HPP
#include <ka/data.hpp>
#include <ka/key_pair.hpp>
#include <pn532/controller.hpp>
#include <sodium/crypto_secretstream_xchacha20poly1305.h>


namespace ka::nfc {

    using ms = std::chrono::milliseconds;
    namespace {
        using namespace std::chrono_literals;
    }

    template <class ...Args>
    using result = pn532::controller::result<Args...>;

    struct p2p_initiator {
        [[nodiscard]] virtual result<mlab::bin_data> communicate(mlab::bin_data const &data, ms timeout) = 0;

        virtual ~p2p_initiator() = default;
    };

    struct p2p_target {
        [[nodiscard]] virtual result<mlab::bin_data> receive(ms timeout) = 0;
        virtual result<> send(mlab::bin_data const &data, ms timeout) = 0;
        virtual ~p2p_target() = default;
    };

    class pn532_initiator : public p2p_initiator {
        pn532::controller *_controller = nullptr;
        std::uint8_t _idx{};
    public:
        pn532_initiator() = default;
        pn532_initiator(pn532::controller &controller, std::uint8_t log_idx);
        pn532_initiator(pn532_initiator const &) = delete;
        pn532_initiator &operator=(pn532_initiator const &) = delete;
        pn532_initiator(pn532_initiator &&) noexcept = default;
        pn532_initiator &operator=(pn532_initiator &&) noexcept = default;

        [[nodiscard]] result<mlab::bin_data> communicate(mlab::bin_data const &data, ms timeout) override;
    };

    class pn532_target : public p2p_target {
        pn532::controller *_controller = nullptr;
    public:
        static constexpr std::array<std::uint8_t, 10> default_nfcid3 = {0x30, 0xfd, 0xd9, 0x50, 0xdc, 0xaa, 0x69, 0x89, 0x28, 0xe1};

        pn532_target() = default;
        explicit pn532_target(pn532::controller &controller);
        pn532_target(pn532_target const &) = delete;
        pn532_target &operator=(pn532_target const &) = delete;
        pn532_target(pn532_target &&) noexcept = default;
        pn532_target &operator=(pn532_target &&) noexcept = default;

        [[nodiscard]] result<pn532::init_as_target_res> init_as_target(ms timeout = 5s, std::array<std::uint8_t, 10> nfcid_3t = default_nfcid3);

        [[nodiscard]] result<mlab::bin_data> receive(ms timeout) override;
        result<> send(mlab::bin_data const &data, ms timeout) override;
    };

    struct tx_tag {};
    struct rx_tag {};
    struct header_tag {};

    using tx_key = tagged_array<tx_tag, 32>;
    using rx_key = tagged_array<rx_tag, 32>;
    using header = tagged_array<header_tag, crypto_secretstream_xchacha20poly1305_HEADERBYTES>;

    class secure_initiator : public p2p_initiator {
        p2p_initiator *_raw_layer = nullptr;
        crypto_secretstream_xchacha20poly1305_state _tx{};
        crypto_secretstream_xchacha20poly1305_state _rx{};
        header _hdr{};
        bool _did_handshake = false;
        key_pair _kp{};
        mlab::bin_data _buffer{};

        result<> ensure_handshake(ms timeout);
    public:
        secure_initiator() = default;
        secure_initiator(secure_initiator const &) = delete;
        secure_initiator(secure_initiator &&) noexcept = default;
        secure_initiator &operator=(secure_initiator const &) = delete;
        secure_initiator &operator=(secure_initiator &&) noexcept = default;

        secure_initiator(p2p_initiator &raw_layer, key_pair kp);

        [[nodiscard]] result<mlab::bin_data> communicate(mlab::bin_data const &data, ms timeout) override;
    };

    class secure_target : public p2p_target {
        p2p_target *_raw_layer = nullptr;
        crypto_secretstream_xchacha20poly1305_state _tx{};
        crypto_secretstream_xchacha20poly1305_state _rx{};
        header _hdr{};
        bool _did_handshake = false;
        key_pair _kp{};
        mlab::bin_data _buffer{};

        result<> ensure_handshake(ms timeout);
    public:
        secure_target() = default;
        secure_target(secure_target const &) = delete;
        secure_target(secure_target &&) noexcept = default;
        secure_target &operator=(secure_target const &) = delete;
        secure_target &operator=(secure_target &&) noexcept = default;

        secure_target(p2p_target &raw_layer, key_pair kp);

        [[nodiscard]] result<mlab::bin_data> receive(ms timeout) override;
        result<> send(mlab::bin_data const &data, ms timeout) override;
    };
}

#endif//KEYCARD_ACCESS_NFC_P2P_HPP
