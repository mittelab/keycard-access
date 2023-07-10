//
// Created by spak on 1/16/23.
//

#ifndef KEYCARD_ACCESS_SECURE_P2P_HPP
#define KEYCARD_ACCESS_SECURE_P2P_HPP

#include <ka/data.hpp>
#include <ka/key_pair.hpp>
#include <pn532/p2p.hpp>
#include <sodium/crypto_secretstream_xchacha20poly1305.h>


namespace ka::p2p {
    using ms = std::chrono::milliseconds;
    using namespace std::chrono_literals;
    using pn532::result;
    using pn532::p2p::initiator;
    using pn532::p2p::target;

    struct tx_tag {};
    struct rx_tag {};
    struct header_tag {};

    using tx_key = mlab::tagged_array<tx_tag, 32>;
    using rx_key = mlab::tagged_array<rx_tag, 32>;
    using header = mlab::tagged_array<header_tag, crypto_secretstream_xchacha20poly1305_HEADERBYTES>;

    class secure_initiator : public initiator {
        initiator *_raw_layer = nullptr;
        crypto_secretstream_xchacha20poly1305_state _tx{};
        crypto_secretstream_xchacha20poly1305_state _rx{};
        header _hdr{};
        bool _did_handshake = false;
        key_pair _kp{};
        mlab::bin_data _buffer{};
        pub_key _peer_pk{};

    public:
        secure_initiator() = default;
        secure_initiator(secure_initiator const &) = delete;
        secure_initiator(secure_initiator &&) noexcept = default;
        secure_initiator &operator=(secure_initiator const &) = delete;
        secure_initiator &operator=(secure_initiator &&) noexcept = default;

        secure_initiator(initiator &raw_layer, key_pair kp);

        result<pub_key> handshake(ms timeout = 1s);

        [[nodiscard]] inline bool did_handshake() const;
        [[nodiscard]] inline pub_key const &peer_pub_key() const;

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
        pub_key _peer_pk{};

    public:
        secure_target() = default;
        secure_target(secure_target const &) = delete;
        secure_target(secure_target &&) noexcept = default;
        secure_target &operator=(secure_target const &) = delete;
        secure_target &operator=(secure_target &&) noexcept = default;

        secure_target(target &raw_layer, key_pair kp);

        result<pub_key> handshake(ms timeout = 1s);

        [[nodiscard]] inline bool did_handshake() const;
        [[nodiscard]] inline pub_key const &peer_pub_key() const;

        [[nodiscard]] result<mlab::bin_data> receive(ms timeout) override;
        result<> send(mlab::bin_data const &data, ms timeout) override;
    };
}// namespace ka::p2p


namespace ka::p2p {

    bool secure_target::did_handshake() const {
        return _did_handshake;
    }
    pub_key const &secure_target::peer_pub_key() const {
        return _peer_pk;
    }
    bool secure_initiator::did_handshake() const {
        return _did_handshake;
    }
    pub_key const &secure_initiator::peer_pub_key() const {
        return _peer_pk;
    }
}// namespace ka::p2p

#endif//KEYCARD_ACCESS_SECURE_P2P_HPP
