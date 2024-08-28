//
// Created by spak on 19/08/24.
//

#include <kaproto/tcp.hpp>

#include <esp_log.h>
#include <sys/socket.h>

namespace ka::proto {
    const char *to_string(error e) {
        switch (e) {
            case error::timeout:
                return "timeout";
            case error::not_connected:
                return "not connected";
            case error::invalid_argument:
                return "invalid argument";
            case error::system_error:
                return "system error";
            case error::malformed:
                return "malformed";
            case error::crypto_error:
                return "crypto error";
            default:
                return "UNKNOWN";
        }
    }

    tcp_socket::tcp_socket(std::string const &addr, std::uint16_t port) {
        _socket = socket(AF_INET, SOCK_STREAM, IPPROTO_IP);
        if (_socket < 0) {
            ESP_LOGE("KA", "Unable to create socket");
            return;
        }
        sockaddr_in sock_addr{};
        inet_pton(AF_INET, addr.c_str(), &sock_addr.sin_addr);
        sock_addr.sin_family = AF_INET;
        sock_addr.sin_port = htons(port);
        if (const auto connect_result = connect(_socket,
                                                reinterpret_cast<const sockaddr *>(&sock_addr),
                                                sizeof(sock_addr)); connect_result != 0) {
            ESP_LOGE("KA", "Failed to connect: %d", connect_result);
            close();
            return;
        }
        _connected = true;
        ESP_LOGI("KA", "TCP socket connected.");
    }

    r<> tcp_socket::send(mlab::range<std::uint8_t const *> data, ms timeout) {
        if (not*this) {
            return error::not_connected;
        }
        const timeval t{
            .tv_sec = timeout.count() / 1000,
            .tv_usec = 1000 * (long(timeout.count()) % 1000)
        };
        if (0 != setsockopt(_socket, SOL_SOCKET, SO_SNDTIMEO, &t, sizeof(t))) {
            return error_from_errno();
        }
        if (::send(_socket, data.data(), data.size(), 0) < 0) {
            return error_from_errno();
        }
        return mlab::result_success;
    }

    r<> tcp_socket::recv(mlab::range<std::uint8_t *> data, ms timeout) {
        if (not*this) {
            return error::not_connected;
        }
        const timeval t{
            .tv_sec = timeout.count() / 1000,
            .tv_usec = 1000 * (long(timeout.count()) % 1000)
        };
        if (0 != setsockopt(_socket, SOL_SOCKET, SO_RCVTIMEO, &t, sizeof(t))) {
            return error_from_errno();
        }
        if (::recv(_socket, data.data(), data.size(), 0) < 0) {
            return error_from_errno();
        }
        return mlab::result_success;
    }


    void tcp_socket::close() {
        if (_socket >= 0) {
            if (_connected) {
                shutdown(_socket, 0);
                _connected = false;
            }
            ::close(_socket);
            _socket = -1;
        }
    }


    tcp_socket::~tcp_socket() {
        close();
    }
};
