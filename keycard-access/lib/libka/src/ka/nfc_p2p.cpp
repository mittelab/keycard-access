//
// Created by spak on 1/16/23.
//

#include <ka/nfc_p2p.hpp>
#include <sodium/crypto_kx.h>

namespace ka::nfc {
    static_assert(tx_key::array_size == crypto_kx_SESSIONKEYBYTES);
    static_assert(rx_key::array_size == crypto_kx_SESSIONKEYBYTES);
    static_assert(raw_pub_key::array_size == crypto_kx_PUBLICKEYBYTES);
    static_assert(raw_sec_key::array_size == crypto_kx_SECRETKEYBYTES);

    result<mlab::bin_data> pn532_initiator::communicate(mlab::bin_data const &data, ms timeout) {
        if (_controller == nullptr) {
            return pn532::channel::error::failure;
        }
        if (auto r = _controller->initiator_data_exchange(_idx, data, timeout); r) {
            return std::move(r->second);
        } else {
            return r.error();
        }
    }

    [[nodiscard]] result<mlab::bin_data> pn532_target::receive(ms timeout) {
        if (_controller == nullptr) {
            return pn532::channel::error::failure;
        }
        if (auto r = _controller->target_get_data(timeout); r) {
            return std::move(r->second);
        } else {
            return r.error();
        }
    }

    [[nodiscard]] result<> pn532_target::send(mlab::bin_data const &data, ms timeout) {
        if (_controller == nullptr) {
            return pn532::channel::error::failure;
        }
        if (const auto r = _controller->target_set_data(data, timeout); not r) {
            return r.error();
        }
        return mlab::result_success;
    }

    pn532_initiator::pn532_initiator(pn532::controller &controller, std::uint8_t log_idx)
        : _controller{&controller}, _idx{log_idx} {}

    pn532_target::pn532_target(pn532::controller &controller)
        : _controller{&controller} {}

    result<pn532::init_as_target_res> pn532_target::init_as_target(ms timeout, std::array<std::uint8_t, 10> nfcid_3t) {
        if (_controller == nullptr) {
            return pn532::channel::error::failure;
        }
        const pn532::mifare_params mp{
                .sens_res = {0x04, 0x00},
                .nfcid_1t = {nfcid_3t[0], nfcid_3t[1], nfcid_3t[2]},
                .sel_res = pn532::bits::sel_res_dep_mask
        };
        const pn532::felica_params fp {
                .nfcid_2t = {nfcid_3t[3], nfcid_3t[4], nfcid_3t[5], nfcid_3t[6], nfcid_3t[7], nfcid_3t[8]},
                .pad = {0xc0, 0xc1, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7},
                .syst_code = {0xff, 0xff}
        };
        return _controller->target_init_as_target(false, true, false, mp, fp, nfcid_3t, {}, {}, timeout);
    }

    secure_initiator::secure_initiator(p2p_initiator &raw_layer, key_pair kp)
        : _raw_layer{&raw_layer}, _tx{}, _rx{}, _hdr{}, _did_handshake{false}, _kp{kp} {}

    secure_target::secure_target(p2p_target &raw_layer, key_pair kp)
        : _raw_layer{&raw_layer}, _tx{}, _rx{}, _hdr{}, _did_handshake{false}, _kp{kp} {}

    result<> secure_target::ensure_handshake(ms timeout) {
        if (_did_handshake) {
            return mlab::result_success;
        } else if (_raw_layer == nullptr) {
            return pn532::channel::error::failure;
        }
        mlab::reduce_timeout rt{timeout};
        raw_pub_key initiator_pub_key{};
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
            std::copy_n(std::begin(*r), raw_pub_key::array_size, std::begin(initiator_pub_key));
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
                         rx.data(), tx.data(), _kp.raw_pk().data(), _kp.raw_sk().data(), initiator_pub_key.data()))
        {
            ESP_LOGE("KA", "Suspicious %s public key!", "initiator");
            return pn532::channel::error::failure;
        }
        crypto_secretstream_xchacha20poly1305_init_push(&_tx, _hdr.data(), tx.data());
        crypto_secretstream_xchacha20poly1305_init_pull(&_rx, initiator_header.data(), rx.data());
        // Send our header
        if (const auto r = _raw_layer->send(mlab::bin_data::chain(_hdr), rt.remaining()); r) {
            _did_handshake = true;
            return mlab::result_success;
        } else {
            return r.error();
        }
    }

    result<> secure_initiator::ensure_handshake(ms timeout) {
        if (_did_handshake) {
            return mlab::result_success;
        } else if (_raw_layer == nullptr) {
            return pn532::channel::error::failure;
        }
        mlab::reduce_timeout rt{timeout};
        raw_pub_key target_pub_key{};
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
            std::copy_n(std::begin(*r), raw_pub_key::array_size, std::begin(target_pub_key));
        }
        // Derive the keys
        if (0 != crypto_kx_client_session_keys(
                         rx.data(), tx.data(), _kp.raw_pk().data(), _kp.raw_sk().data(), target_pub_key.data()))
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
        return mlab::result_success;
    }

    result<mlab::bin_data> secure_initiator::communicate(const mlab::bin_data &data, ms timeout) {
        if (_raw_layer == nullptr) {
            return pn532::channel::error::failure;
        }
        mlab::reduce_timeout rt{timeout};
        if (const auto r = ensure_handshake(rt.remaining()); not r) {
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
        if (const auto r = ensure_handshake(rt.remaining()); not r) {
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
        if (const auto r = ensure_handshake(rt.remaining()); not r) {
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