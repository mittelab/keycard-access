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
#include <future>
#include <mlab/time.hpp>

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

        [[nodiscard]] std::size_t hash() const;

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
        std::timed_mutex _pending_requests_mutex = {};
        std::unordered_map<uuid, std::promise<json> > _pending_requests;

        [[nodiscard]] r<> send_raw_packet(mlab::range<std::uint8_t const *> packet, ms timeout);

        [[nodiscard]] r<mlab::bin_data> recv_raw_packet(ms timeout);

        [[nodiscard]] r<> handshake_as_client(ms timeout);

        [[nodiscard]] r<> handshake_as_server(ms timeout);

        [[nodiscard]] r<> send_packet(mlab::range<std::uint8_t const *> packet, ms timeout);

        [[nodiscard]] r<mlab::bin_data> recv_packet(ms timeout);

        [[nodiscard]] r<std::future<json> > store_send_request(json req_body, ms timeout);

        [[nodiscard]] r<json> await_response(std::future<json> &fut, ms timeout);

    public:
        /**
         * Maximum packet size that can be sent or received. This limit is imposed to prevent filling the ESP RAM.
         */
        static constexpr std::size_t max_packet_size = 16 * 1024 * 1024;

        secure_channel() = default;

        template<class... Args>
        [[nodiscard]] r<std::future<json> > request(std::string_view method_name, Args &&... args, ms timeout);

        template<class R = json>
        [[nodiscard]] r<R> response(std::future<json> &fut, ms timeout);

        template<class R, class... Args>
        [[nodiscard]] r<R> invoke(std::string_view method_name, Args &&... args, ms timeout);

        [[nodiscard]] inline channel_status status() const;

        inline explicit operator bool() const;

        [[nodiscard]] r<> connect(std::string_view host, std::uint16_t port);

        void disconnect();
    };
}

template<>
struct std::hash<ka::proto::uuid> {
    std::size_t operator()(ka::proto::uuid const &u) const {
        return u.hash();
    }
};

namespace ka::proto {
    inline channel_status secure_channel::status() const {
        return _status;
    }

    inline secure_channel::operator bool() const {
        return status() == channel_status::ready;
    }

    template<class... Args>
    r<std::future<json> > secure_channel::request(std::string_view method_name, Args &&... args, ms timeout) {
        const auto request_id = uuid{randomize};
        const json request{
            {"jsonrpc", "2.0"},
            {"method", method_name},
            {"params", std::forward<Args>(args)...}
        };
        return store_send_request(request, timeout);
    }

    template<class R>
    r<R> secure_channel::response(std::future<json> &fut, ms timeout) {
        if (const auto res = await_response(fut, timeout); res) {
            return res->get<R>();
        } else {
            return res.error();
        }
    }

    template<class R, class... Args>
    r<R> secure_channel::invoke(std::string_view method_name, Args &&... args, ms timeout) {
        mlab::reduce_timeout rt{timeout};
        auto r_req = request(method_name, std::forward<Args>(args)..., rt.remaining());
        if (not r_req) {
            return r_req.error();
        }
        return response<R>(*r_req, rt.remaining());
    }
}

#endif //SECURE_HPP
