//
// Created by spak on 25/08/24.
//

#include <kaproto/secure.hpp>
#include <mlab/time.hpp>
#include <mutex>
#include <rom/uart.h>
#include <sodium/crypto_kx.h>
#include <sodium/crypto_secretstream_xchacha20poly1305.h>
#include <sodium/randombytes.h>
#include <mlab/result_macro.hpp>

namespace ka::proto {
    uuid::uuid(randomize_t) : _data{} {
        esp_fill_random(_data.data(), _data.size());
        _data[6] = 0x40 | (_data[6] & 0xf);
        _data[8] = 0x80 | (_data[8] & 0b00111111);
    }

    std::string uuid::to_string() const {
        std::string buffer;
        buffer.resize(37);
        std::snprintf(buffer.data(), buffer.size(),
                      "%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x",
                      _data[0], _data[1], _data[2], _data[3], _data[4], _data[5], _data[6], _data[7],
                      _data[8], _data[9], _data[10], _data[11], _data[12], _data[13], _data[14], _data[15]
        );
        buffer.resize(36);
        return buffer;
    }

    r<> secure_channel::send_raw_packet(mlab::bin_data const &packet, ms timeout) {
        if (packet.size() > max_packet_size) {
            return error::invalid_argument;
        }
        const mlab::reduce_timeout rt{timeout};
        const std::unique_lock lock{_send_mutex, rt.remaining()};
        if (not lock) {
            return error::timeout;
        }
        /**
         * @todo Use std::array and lsb32 in a smarter way
         **/
        const mlab::bin_data packet_length = mlab::bin_data::chain(mlab::prealloc(4), mlab::lsb32, packet.size());
        if (const auto res = _socket.send(packet_length.data_view(), rt.remaining()); not res) {
            return res;
        }
        return _socket.send(packet.data_view(), rt.remaining());
    }

    r<mlab::bin_data> secure_channel::recv_raw_packet(ms timeout) {
        const mlab::reduce_timeout rt{timeout};
        const std::unique_lock lock{_recv_mutex, rt.remaining()};
        if (not lock) {
            return error::timeout;
        }
        mlab::bin_data buffer{mlab::prealloc(4)};
        if (const auto res = _socket.recv(buffer.data_view(), rt.remaining()); not res) {
            return res.error();
        }
        // Extract the packet length
        std::uint32_t packet_length = 0;
        mlab::bin_stream s{buffer};
        s >> mlab::lsb32 >> packet_length;
        if (s.bad() or packet_length == 0 or packet_length > max_packet_size) {
            return error::malformed;
        }
        // Allocate the buffer
        buffer.resize(packet_length);
        if (const auto res = _socket.recv(buffer.data_view(), rt.remaining()); not res) {
            return res.error();
        }
        return buffer;
    }

    namespace {
        struct handshake_state {
            mlab::bin_data own_ephemeral_pk{};
            mlab::bin_data peer_ephemeral_pk{};

            std::array<std::uint8_t, crypto_kx_SECRETKEYBYTES> own_ephemeral_sk{};

            std::array<std::uint8_t, crypto_kx_SESSIONKEYBYTES> rx_key{};
            std::array<std::uint8_t, crypto_kx_SESSIONKEYBYTES> tx_key{};

            handshake_state() {
                own_ephemeral_pk.resize(crypto_kx_PUBLICKEYBYTES);
                crypto_kx_keypair(own_ephemeral_pk.data(), own_ephemeral_sk.data());
                // Safety measure in case we accidentally make use of these keys:
                randombytes_buf(tx_key.data(), tx_key.size());
                randombytes_buf(rx_key.data(), rx_key.size());
            }

            [[nodiscard]] r<> recv_peer_ephemeral_pk(r<mlab::bin_data> packet) {
                if (not packet) {
                    return packet.error();
                }
                if (packet->size() != crypto_kx_PUBLICKEYBYTES) {
                    ESP_LOGE("KA", "Received invalid length peer %s", "public key");
                    return error::malformed;
                }
                peer_ephemeral_pk = std::move(*packet);
                return mlab::result_success;
            }

            [[nodiscard]] r<> derive_session_keys(bool is_server) {
                if (peer_ephemeral_pk.size() != crypto_kx_PUBLICKEYBYTES
                    or own_ephemeral_pk.size() != crypto_kx_PUBLICKEYBYTES) {
                    return error::system_error;
                }

                // Choose derivation function based on the argument
                const auto &crypto_kx_session_keys = is_server
                                                         ? crypto_kx_server_session_keys
                                                         : crypto_kx_client_session_keys;

                if (0 != crypto_kx_session_keys(rx_key.data(), tx_key.data(), own_ephemeral_pk.data(),
                                                own_ephemeral_sk.data(), peer_ephemeral_pk.data())) {
                    ESP_LOGE("KA", "Unable to derive ephemeral session keys.");
                    return error::crypto_error;
                }
                return mlab::result_success;
            }

            [[nodiscard]] mlab::bin_data prepare_push_packet(
                crypto_secretstream_xchacha20poly1305_state &send_state) const {
                mlab::bin_data packet;
                packet.resize(crypto_secretstream_xchacha20poly1305_HEADERBYTES);
                crypto_secretstream_xchacha20poly1305_init_push(&send_state, packet.data(), tx_key.data());
                return packet;
            }

            [[nodiscard]] r<> recv_peer_pull_packet(crypto_secretstream_xchacha20poly1305_state &recv_state,
                                                    r<mlab::bin_data> packet) const {
                if (not packet) {
                    return packet.error();
                }
                if (packet->size() != crypto_secretstream_xchacha20poly1305_HEADERBYTES) {
                    ESP_LOGE("KA", "Received invalid length peer %s", "header packet");
                    return error::malformed;
                }
                crypto_secretstream_xchacha20poly1305_init_pull(&recv_state, packet->data(), rx_key.data());
                return mlab::result_success;
            }
        };
    }

    r<> secure_channel::handshake_as_client(ms timeout) {
        const mlab::reduce_timeout rt{timeout};

        // Generate own keypair
        handshake_state state{};

        // Send our own ephemeral PK
        TRY(send_raw_packet(state.own_ephemeral_pk, rt.remaining()));
        // Retrieve the peer ephemeral PK
        TRY(state.recv_peer_ephemeral_pk(recv_raw_packet(rt.remaining())));

        // Derive the session keys
        TRY(state.derive_session_keys(false));

        // Prepare and send the initialization packet
        TRY(send_raw_packet(state.prepare_push_packet(_send_state), rt.remaining()));
        // Receive the peer's packet to initialize our own recv state
        TRY(state.recv_peer_pull_packet(_recv_state, recv_raw_packet(rt.remaining())));

        return mlab::result_success;
    }

    r<> secure_channel::handshake_as_server(ms timeout) {
        const mlab::reduce_timeout rt{timeout};

        // Generate own keypair
        handshake_state state{};

        // Retrieve the peer ephemeral PK
        TRY(state.recv_peer_ephemeral_pk(recv_raw_packet(rt.remaining())));
        // Send our own ephemeral PK
        TRY(send_raw_packet(state.own_ephemeral_pk, rt.remaining()));

        // Derive the session keys
        TRY(state.derive_session_keys(true));

        // Receive the peer's packet to initialize our own recv state
        TRY(state.recv_peer_pull_packet(_recv_state, recv_raw_packet(rt.remaining())));
        // Prepare and send the initialization packet
        TRY(send_raw_packet(state.prepare_push_packet(_send_state), rt.remaining()));

        return mlab::result_success;
    }


    r<> secure_channel::send_packet(mlab::bin_data const &packet, ms timeout) {
        mlab::bin_data ciphertext;
        ciphertext.resize(packet.size() + crypto_secretstream_xchacha20poly1305_ABYTES);
        // Unfortuntately it doesn't seem to allow in-place encryption
        if (0 != crypto_secretstream_xchacha20poly1305_push(
                &_send_state, ciphertext.data(), nullptr,
                packet.data(), packet.size(), nullptr, 0, 0)) {
            return error::crypto_error;
        }
        return send_raw_packet(ciphertext, timeout);
    }

    r<mlab::bin_data> secure_channel::recv_packet(ms timeout) {
        auto recv_res = recv_raw_packet(timeout);
        if (not recv_res) {
            return recv_res.error();
        }
        // This one instead can be used in-place
        if (0 != crypto_secretstream_xchacha20poly1305_pull(
                &_recv_state, recv_res->data(), nullptr, nullptr,
                recv_res->data(), recv_res->size(), nullptr, 0)) {
            return error::crypto_error;
        }
        // Truncate by crypto_secretstream_xchacha20poly1305_ABYTES
        recv_res->resize(recv_res->size() - crypto_secretstream_xchacha20poly1305_ABYTES);
        return recv_res;
    }
}
