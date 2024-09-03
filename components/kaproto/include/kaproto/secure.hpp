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

    using json_value_type = json::value_t;

    struct any_json_value_t {} static constexpr any_json_value = {};

    template <class T>
    concept json_equatable = requires (T a) { std::declval<json const &>() == a; };

    template <class Fn>
    concept json_validation_predicate = std::is_invocable_r_v<bool, Fn, json const &>;

    /**
     * @brief Shorthand function to validate an entry in a Json object.
     *
     * This function will check
     *  - if an entry with key @p key exists in @p j.
     *  - If it does not exist, it will return true of @p omittable, and false otherwise.
     *  - If it does exist, it checks if its type is one of `Types`. If `Types` is not empty and this is not the case,
     *    it returns false. If `Types` is empty, any type is accepted.
     *  - At this point, we know @p j contains a key @p key, possibly with type being one of `Types`.
     *  - If @p value_or_predicate is @ref any_json_value, then the function returns true.
     *  - If @p value_or_predicate is callable with signature `bool predicate(json const &)`, then @p value_or_predicate
     *    is called with the value of the entry @p key, and its return value returned.
     *  - Otherwise, @p value_or predicate is compared to the value entry.
     *
     * @code
     * json j; // j = ...
     * // j must have a key "child" of any value:
     * json_validate(j, "child");
     * // j must have a key "child" which must be a string
     * json_validate<json_value_type::string>(j, "child");
     * // j must have a key "child" which must be a string or an unsigned integer
     * json_validate<json_value_type::string, json_value_type::number_unsigned>(j, "child");
     * // If j has a "count" key, it must be an unsigned integer
     * json_validate<json_value_type::number_unsigned>(j, "count", true);
     * // j must have a key "count" which must be an unsigned integer of value exactly 0
     * json_validate<json_value_type::number_unsigned>(j, "count", false, 0);
     * // If j has a "count" key, it must be an unsigned integer of value exactly 0
     * json_validate<json_value_type::number_unsigned>(j, "count", true, 0);
     * // If j has a "parent" key, it must be either a string or null
     * json_validate<json_value_type::string, json_value_type::null>(j, "parent", true);
     * // j must have a "parent" key, which is either a string or null
     * json_validate<json_value_type::string, json_value_type::null>(j, "parent", false);
     * @endcode
     *
     * @code
     * bool child_validator(json const &); // ...
     *
     * // j must have a "child" key of type object, which must pass `child_validator`,
     * //  i.e. child_validator(j["child"]) must be true.
     * json_validate<json_value_type::object>(j, "child", false, child_validator);
     * @endcode
     *
     * @code
     * // j must have either a "result" field of any type, or an "error" field of type object, which itself must be
     * // validated by error_validator.
     * bool error_validator(json const &); // ...
     *
     * bool validator(json const &j) {
     *     if (json_validate(j, "result", false)) {
     *         return not json_validate(j, "error", false);
     *     }
     *     return json_validate<json_value_type::object>(k, "error", false, error_validator);
     * }
     * @endcode
     *
     * @tparam Types List of accepted @ref json_value_type for this entry. If empty, any type is accepted.
     * @tparam P Either a value that can be compared to @ref json type, or a predicate matching the call signature
     *  `bool predicate(json const &)` which validates the entry.
     * @param j Json object for which to validate the entry
     * @param key Key name to test
     * @param omittable Whether the absence of @p key is considered a failure or not. True to allow omission,
     *  false to consider it a failure.
     * @param value_or_predicate If this is an instance of @ref any_json_value_t (i.e. @ref any_json_value), any value
     *  of a valid type is considered valid. If this is a validation predicate, (i.e. has the signature
     *  `bool predicate(json const &)`), then this predicate will be called with the value of the entry, and determine
     *  its validity. Otherwise, it is compared to the value of the entry to determine validity.
     * @return A boolean expressing whether the value entry passes the checks.
     */
    template <json_value_type... Types, class P = any_json_value_t>
        requires json_equatable<P> or json_validation_predicate<P> or std::is_same_v<P, any_json_value_t>
    [[nodiscard]] bool json_validate(json const &j, std::string_view key,
                                     bool omittable = false, P value_or_predicate = {});

    [[nodiscard]] bool jsonrpc_validate_request(json const &j);
    [[nodiscard]] bool jsonrpc_validate_response(json const &j);
    [[nodiscard]] bool jsonrpc_validate_error(json const &j);

    class uuid {
        std::array<std::uint8_t, 16> _data;

    public:
        uuid(): _data{} {
        }

        [[nodiscard]] std::size_t hash() const;

        explicit uuid(randomize_t);

        [[nodiscard]] std::string to_string() const;

        [[nodiscard]] static std::optional<uuid> from_string(std::string_view s);
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

        template <class... Args>
        [[nodiscard]] r<std::future<json> > request(std::string_view method_name, Args &&... args, ms timeout);

        template <class R = json>
        [[nodiscard]] r<R> response(std::future<json> &fut, ms timeout);

        template <class R, class... Args>
        [[nodiscard]] r<R> invoke(std::string_view method_name, Args &&... args, ms timeout);

        [[nodiscard]] inline channel_status status() const;

        inline explicit operator bool() const;

        [[nodiscard]] r<> connect(std::string_view host, std::uint16_t port);

        void disconnect();
    };
}

template <>
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

    template <class... Args>
    r<std::future<json> > secure_channel::request(std::string_view method_name, Args &&... args, ms timeout) {
        const auto request_id = uuid{randomize};
        const json request{
            {"jsonrpc", "2.0"},
            {"method", method_name},
            {"params", std::forward<Args>(args)...}
        };
        return store_send_request(request, timeout);
    }

    template <class R>
    r<R> secure_channel::response(std::future<json> &fut, ms timeout) {
        if (const auto res = await_response(fut, timeout); res) {
            return res->get<R>();
        } else {
            return res.error();
        }
    }

    template <class R, class... Args>
    r<R> secure_channel::invoke(std::string_view method_name, Args &&... args, ms timeout) {
        mlab::reduce_timeout rt{timeout};
        auto r_req = request(method_name, std::forward<Args>(args)..., rt.remaining());
        if (not r_req) {
            return r_req.error();
        }
        return response<R>(*r_req, rt.remaining());
    }

    template <json_value_type... Types, class P>
        requires json_equatable<P> or json_validation_predicate<P> or std::is_same_v<P, any_json_value_t>
    [[nodiscard]] bool json_validate(json const &j, std::string_view key, bool omittable, P value_or_predicate) {
        if (const auto it = j.find(key); it != std::end(j)) {
            if constexpr (sizeof Types == 0) {
                return true;
            } else if (((it->type() == Types) or ...)) {
                if constexpr (std::is_same_v<P, any_json_value_t>) {
                    return true;
                } else if constexpr (std::is_invocable_r_v<bool, P, json const &>) {
                    return value_or_predicate(*it);
                } else {
                    return *it == value_or_predicate;
                }
            }
        } else if (omittable) {
            return true;
        }
        return false;
    }


}

#endif //SECURE_HPP
