//
// Created by spak on 1/16/23.
//

#ifndef KEYCARD_ACCESS_SECURE_P2P_HPP
#define KEYCARD_ACCESS_SECURE_P2P_HPP

#include <ka/data.hpp>
#include <ka/key_pair.hpp>
#include <pn532/p2p.hpp>
#include <sodium/crypto_secretstream_xchacha20poly1305.h>


namespace ka::nfc {
    namespace {
        using namespace pn532::p2p;
    }

    struct tx_tag {};
    struct rx_tag {};
    struct header_tag {};

    using tx_key = tagged_array<tx_tag, 32>;
    using rx_key = tagged_array<rx_tag, 32>;
    using header = tagged_array<header_tag, crypto_secretstream_xchacha20poly1305_HEADERBYTES>;

    class secure_initiator : public initiator {
        initiator *_raw_layer = nullptr;
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

        secure_initiator(initiator &raw_layer, key_pair kp);

        [[nodiscard]] result<mlab::bin_data> communicate(mlab::bin_data const &data, ms timeout) override;
    };

    class secure_target : public target {
        target *_raw_layer = nullptr;
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

        secure_target(target &raw_layer, key_pair kp);

        [[nodiscard]] result<mlab::bin_data> receive(ms timeout) override;
        result<> send(mlab::bin_data const &data, ms timeout) override;
    };
}

#endif//KEYCARD_ACCESS_SECURE_P2P_HPP
