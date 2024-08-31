//
// Created by spak on 25/08/24.
//

#ifndef SECURE_HPP
#define SECURE_HPP

#include <kaproto/tcp.hpp>
#include <mutex>
#include <sodium/crypto_secretstream_xchacha20poly1305.h>
#include <json/json.hpp>
#include <ka/data.hpp>

namespace ka::proto {
    enum struct channel_status {
        idle,
        handshaking,
        ready,
        disconnecting
    };

    using json = nlohmann::json;

    class uuid {
        std::array<std::uint8_t, 16> _data;

    public:
        uuid(): _data{} {
        }

        explicit uuid(randomize_t);

        [[nodiscard]] std::string to_string() const;
    };

    class secure_channel {
        tcp_socket _socket = {};
        channel_status _status = channel_status::idle;
        std::timed_mutex _recv_mutex = {};
        std::timed_mutex _send_mutex = {};
        crypto_secretstream_xchacha20poly1305_state _recv_state = {};
        crypto_secretstream_xchacha20poly1305_state _send_state = {};

        [[nodiscard]] r<> send_raw_packet(mlab::bin_data const &packet, ms timeout);

        [[nodiscard]] r<mlab::bin_data> recv_raw_packet(ms timeout);

        [[nodiscard]] r<> handshake_as_client(ms timeout);

        [[nodiscard]] r<> handshake_as_server(ms timeout);

        [[nodiscard]] r<> send_packet(mlab::bin_data const &packet, ms timeout);

        [[nodiscard]] r<mlab::bin_data> recv_packet(ms timeout);

    public:
        /**
         * Maximum packet size that can be sent or received. This limit is imposed to prevent filling the ESP RAM.
         */
        static constexpr std::size_t max_packet_size = 16 * 1024 * 1024;

        secure_channel() = default;

        [[nodiscard]] inline channel_status status() const;

        inline explicit operator bool() const;

        [[nodiscard]] r<> connect(std::string const &host, std::uint16_t port);

        void disconnect();
    };
}

namespace ka::proto {
    inline channel_status secure_channel::status() const {
        return _status;
    }

    inline secure_channel::operator bool() const {
        return status() == channel_status::ready;
    }
}

#endif //SECURE_HPP
