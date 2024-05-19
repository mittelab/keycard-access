//
// Created by spak on 5/31/23.
//

#ifndef KEYCARD_ACCESS_HTTP_HPP
#define KEYCARD_ACCESS_HTTP_HPP

#include <chrono>
#include <memory>
#include <mlab/bin_data.hpp>

namespace ka {
    namespace {
        using namespace std::chrono_literals;
    }

    using http_status = unsigned;

    class http_client {
        class http_client_impl;
        static void http_client_deleter(http_client_impl *c);

        /**
         * @note An opaque pointer, with a custom deleter so that the size of @ref wifi_impl needs not to be known.
         */
        std::unique_ptr<http_client_impl, void (*)(http_client_impl *)> _pimpl;

    public:
        explicit http_client(std::string_view url, std::chrono::milliseconds timeout = 5s);

        [[nodiscard]] std::pair<http_status, mlab::bin_data> get();

        [[nodiscard]] static std::pair<http_status, mlab::bin_data> get(std::string_view url, std::chrono::milliseconds timeout = 5s);

        [[nodiscard]] static esp_http_client_config_t get_default_config(std::string_view url, std::chrono::milliseconds timeout = 5s);
    };
}// namespace ka

#endif//KEYCARD_ACCESS_HTTP_HPP
