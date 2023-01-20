//
// Created by spak on 1/16/23.
//

#include <ka/secure_p2p.hpp>
#include <sodium/crypto_kx.h>

namespace ka::p2p {
    static_assert(tx_key::array_size == crypto_kx_SESSIONKEYBYTES);
    static_assert(rx_key::array_size == crypto_kx_SESSIONKEYBYTES);
    static_assert(raw_pub_key::array_size == crypto_kx_PUBLICKEYBYTES);
    static_assert(raw_sec_key::array_size == crypto_kx_SECRETKEYBYTES);

    secure_initiator::secure_initiator(initiator &raw_layer, key_pair kp)
        : _raw_layer{&raw_layer}, _tx{}, _rx{}, _hdr{}, _did_handshake{false}, _kp{kp} {}

    secure_target::secure_target(target &raw_layer, key_pair kp)
        : _raw_layer{&raw_layer}, _tx{}, _rx{}, _hdr{}, _did_handshake{false}, _kp{kp} {}

    result<raw_pub_key> secure_target::handshake(ms timeout) {
        if (_did_handshake) {
            return peer_pub_key();
        } else if (_raw_layer == nullptr) {
            return pn532::channel::error::failure;
        }
        mlab::reduce_timeout rt{timeout};
        tx_key tx{};
        rx_key rx{};
        header initiator_header{};
        // Retrieve public key
        if (const auto r = _raw_layer->receive(rt.remaining()); not r) {
            return r.error();
        } else if (r->size() != raw_pub_key::array_size) {
            ESP_LOGE("KA", "Invalid %s size %d.", "initiator pubkey", r->size());
            return pn532::channel::error::comm_malformed;
        } else {
            std::copy_n(std::begin(*r), raw_pub_key::array_size, std::begin(_peer_pk));
        }
        // Send our public key
        if (const auto r = _raw_layer->send(mlab::bin_data::chain(_kp.raw_pk()), rt.remaining()); not r) {
            return r.error();
        }
        // Receive the initiator header
        if (const auto r = _raw_layer->receive(rt.remaining()); not r) {
            return r.error();
        } else if (r->size() != header::array_size) {
            ESP_LOGE("KA", "Invalid %s size %d.", "initiator header", r->size());
        } else {
            std::copy_n(std::begin(*r), header::array_size, std::begin(initiator_header));
        }
        // Derive the keys
        if (0 != crypto_kx_client_session_keys(
                         rx.data(), tx.data(), _kp.raw_pk().data(), _kp.raw_sk().data(), _peer_pk.data()))
        {
            ESP_LOGE("KA", "Suspicious %s public key!", "initiator");
            return pn532::channel::error::failure;
        }
        crypto_secretstream_xchacha20poly1305_init_push(&_tx, _hdr.data(), tx.data());
        crypto_secretstream_xchacha20poly1305_init_pull(&_rx, initiator_header.data(), rx.data());
        // Send our header
        if (const auto r = _raw_layer->send(mlab::bin_data::chain(_hdr), rt.remaining()); r) {
            ESP_LOG_BUFFER_HEX_LEVEL("RX KEY", rx.data(), 32, ESP_LOG_DEBUG);
            ESP_LOG_BUFFER_HEX_LEVEL("TX KEY", tx.data(), 32, ESP_LOG_DEBUG);
            _did_handshake = true;
            return peer_pub_key();
        } else {
            return r.error();
        }
    }

    result<raw_pub_key> secure_initiator::handshake(ms timeout) {
        if (_did_handshake) {
            return peer_pub_key();
        } else if (_raw_layer == nullptr) {
            return pn532::channel::error::failure;
        }
        mlab::reduce_timeout rt{timeout};
        tx_key tx{};
        rx_key rx{};
        header target_header{};
        // Send our public key and retrieve the target's
        if (const auto r = _raw_layer->communicate(mlab::bin_data::chain(_kp.raw_pk()), rt.remaining()); not r) {
            return r.error();
        } else if (r->size() != raw_pub_key::array_size) {
            ESP_LOGE("KA", "Invalid %s size %d.", "target pubkey", r->size());
            return pn532::channel::error::comm_malformed;
        } else {
            std::copy_n(std::begin(*r), raw_pub_key::array_size, std::begin(_peer_pk));
        }
        // Derive the keys
        if (0 != crypto_kx_server_session_keys(
                         rx.data(), tx.data(), _kp.raw_pk().data(), _kp.raw_sk().data(), _peer_pk.data()))
        {
            ESP_LOGE("KA", "Suspicious %s public key!", "initiator");
            return pn532::channel::error::failure;
        }
        // Setup up only tx, and exchange headers
        crypto_secretstream_xchacha20poly1305_init_push(&_tx, _hdr.data(), tx.data());
        if (const auto r = _raw_layer->communicate(mlab::bin_data::chain(_hdr), rt.remaining()); not r) {
            return r.error();
        } else if (r->size() != header::array_size) {
            ESP_LOGE("KA", "Invalid %s size %d.", "target header", r->size());
        } else {
            std::copy_n(std::begin(*r), header::array_size, std::begin(target_header));
        }
        // Can now set up rx
        crypto_secretstream_xchacha20poly1305_init_pull(&_rx, target_header.data(), rx.data());
        _did_handshake = true;
        ESP_LOG_BUFFER_HEX_LEVEL("RX KEY", rx.data(), 32, ESP_LOG_DEBUG);
        ESP_LOG_BUFFER_HEX_LEVEL("TX KEY", tx.data(), 32, ESP_LOG_DEBUG);
        return peer_pub_key();
    }

    result<mlab::bin_data> secure_initiator::communicate(const mlab::bin_data &data, ms timeout) {
        if (_raw_layer == nullptr) {
            return pn532::channel::error::failure;
        }
        mlab::reduce_timeout rt{timeout};
        if (const auto r = handshake(rt.remaining()); not r) {
            return r.error();
        }
        _buffer.resize(data.size() + crypto_secretstream_xchacha20poly1305_ABYTES);
        crypto_secretstream_xchacha20poly1305_push(&_tx, _buffer.data(), nullptr, data.data(), data.size(), nullptr, 0, 0);
        if (const auto r = _raw_layer->communicate(_buffer, rt.remaining()); not r) {
            return r.error();
        } else if (r->size() < crypto_secretstream_xchacha20poly1305_ABYTES) {
            ESP_LOGE("KA", "Invalid %s size %d.", "received msg", r->size());
            return pn532::channel::error::comm_malformed;
        } else {
            _buffer.resize(r->size() - crypto_secretstream_xchacha20poly1305_ABYTES);
            if (0 != crypto_secretstream_xchacha20poly1305_pull(
                             &_rx, _buffer.data(), nullptr, nullptr, r->data(), r->size(), nullptr, 0)) {
                ESP_LOGE("KA", "Failed decrypting incoming message.");
                return pn532::channel::error::failure;
            }
            return _buffer;
        }
    }

    result<mlab::bin_data> secure_target::receive(ms timeout) {
        if (_raw_layer == nullptr) {
            return pn532::channel::error::failure;
        }
        mlab::reduce_timeout rt{timeout};
        if (const auto r = handshake(rt.remaining()); not r) {
            return r.error();
        }
        if (const auto r = _raw_layer->receive(rt.remaining()); not r) {
            return r.error();
        } else if (r->size() < crypto_secretstream_xchacha20poly1305_ABYTES) {
            ESP_LOGE("KA", "Invalid %s size %d.", "received msg", r->size());
            return pn532::channel::error::comm_malformed;
        } else {
            _buffer.resize(r->size() - crypto_secretstream_xchacha20poly1305_ABYTES);
            if (0 != crypto_secretstream_xchacha20poly1305_pull(
                             &_rx, _buffer.data(), nullptr, nullptr, r->data(), r->size(), nullptr, 0)) {
                ESP_LOGE("KA", "Failed decrypting incoming message.");
                return pn532::channel::error::failure;
            }
            return _buffer;
        }
    }

    result<> secure_target::send(const mlab::bin_data &data, ms timeout) {
        if (_raw_layer == nullptr) {
            return pn532::channel::error::failure;
        }
        mlab::reduce_timeout rt{timeout};
        if (const auto r = handshake(rt.remaining()); not r) {
            return r.error();
        }
        _buffer.resize(data.size() + crypto_secretstream_xchacha20poly1305_ABYTES);
        crypto_secretstream_xchacha20poly1305_push(&_tx, _buffer.data(), nullptr, data.data(), data.size(), nullptr, 0, 0);
        if (const auto r = _raw_layer->send(_buffer, rt.remaining()); not r) {
            return r.error();
        }
        return mlab::result_success;
    }
}