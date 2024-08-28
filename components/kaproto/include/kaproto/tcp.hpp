//
// Created by spak on 19/08/24.
//

#ifndef TCP_HPP
#define TCP_HPP

#include <cstdint>
#include <string>
#include <mlab/bin_data.hpp>
#include <mlab/result.hpp>
#include <chrono>

namespace ka::proto {
    using ms = std::chrono::milliseconds;

    enum struct error {
        timeout, ///@< EAGAIN
        not_connected, ///@< EBADF, ENOTCONN, ENOTSOCK, EHOSTUNREACH, ECONNREFUSED, EHOSTDOWN, ENETDOWN, ECONNRESET
        invalid_argument, ///@< EACCES, EFAULT, EMSGSIZE, EADDRNOTAVAIL
        system_error, ///@< ENOBUFS, EISCONN, EPIPE, EMFILE, EINTR
        malformed, ///@< Custom
        crypto_error
    };

    [[nodiscard]] const char *to_string(error e);

    [[nodiscard]] error error_from_errno();

    template<class... Args>
    using r = mlab::result<error, Args...>;

    class tcp_socket {
        int _socket = -1;
        bool _connected = false;

    public:
        tcp_socket() = default;

        tcp_socket(tcp_socket const &) = delete;

        tcp_socket(tcp_socket &&) = default;

        tcp_socket &operator=(tcp_socket const &) = delete;

        tcp_socket &operator=(tcp_socket &&) = default;

        tcp_socket(std::string const &addr, std::uint16_t port);

        [[nodiscard]] r<> send(mlab::range<std::uint8_t const *> data, ms timeout);

        [[nodiscard]] r<> recv(mlab::range<std::uint8_t *> data, ms timeout);

        inline explicit operator bool() const;

        void close();

        ~tcp_socket();
    };
}

namespace ka::proto {
    tcp_socket::operator bool() const {
        return _socket >= 0 and _connected;
    }
}
#endif //TCP_HPP
