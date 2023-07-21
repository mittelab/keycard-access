//
// Created by spak on 7/18/23.
//

#ifndef KEYCARD_ACCESS_RPC_HPP
#define KEYCARD_ACCESS_RPC_HPP


#include <ka/misc.hpp>
#include <map>
#include <mlab/bin_data.hpp>
#include <mlab/result.hpp>
#include <mlab/strutils.hpp>
#include <mlab/type_name.hpp>
#include <type_traits>
#include <utility>

namespace pn532::p2p {
    struct target;
    struct initiator;
}// namespace pn532::p2p

namespace ka::rpc {

    template <class T>
    struct use_default_serialization : std::false_type {};

    template <class T>
    struct serializer {
        static void serialize(mlab::bin_data &bd, T const &t);
        [[nodiscard]] static auto deserialize(mlab::bin_stream &s);
    };

    enum struct error : std::uint8_t {
        parsing_error = 0,
        unknown_command,
        mismatching_signature,
        transport_error,
        channel_error,
        invalid_argument
    };

    [[nodiscard]] const char *to_string(error e);

    template <class... Args>
    using r = mlab::result<error, Args...>;

    template <class... Args>
    using deserialized_args_tuple_t = std::tuple<decltype(serializer<Args>::deserialize(std::declval<mlab::bin_stream &>()))...>;

    template <class... Args>
    [[nodiscard]] std::optional<deserialized_args_tuple_t<Args...>> deserialize(mlab::bin_stream &s);

    template <class... Args>
    [[nodiscard]] mlab::bin_data serialize(Args... args);

    template <class R, class T, class... Args>
    [[nodiscard]] std::string signature_of(R (T::*)(Args...));

    template <class R, class T, class... Args>
    [[nodiscard]] std::string signature_of(R (T::*)(Args...) const);

    struct command_base {
        std::string signature = {};

        virtual ~command_base() = default;
        explicit command_base(std::string signature_);

        [[nodiscard]] virtual r<mlab::bin_data> command_response(mlab::bin_stream &args) = 0;
    };

    template <class R, class T, class... Args>
    struct templated_command : command_base, ka::target_method<R, T, Args...> {
        using typename ka::target_method<R, T, Args...>::fn_ptr_t;
        using typename ka::target_method<R, T, Args...>::target_ptr_t;

        explicit templated_command(fn_ptr_t method, target_ptr_t ptr);

        [[nodiscard]] r<mlab::bin_data> command_response(mlab::bin_stream &s) override;

    private:
        template <std::size_t... Is>
        [[nodiscard]] r<mlab::bin_data> invoke_with_tuple(std::index_sequence<Is...>, deserialized_args_tuple_t<Args...> t);
    };

    struct bridge_interface_base {
        virtual ~bridge_interface_base() = default;

        [[nodiscard]] virtual r<mlab::bin_data> receive() = 0;
        [[nodiscard]] virtual r<> send(mlab::bin_data data) = 0;
    };

    template <class T>
    using result_wrap_return = std::conditional_t<std::is_void_v<T>, r<>, r<T>>;

    class bridge {
        std::map<std::string, std::unique_ptr<command_base>> _cmds;
        std::unique_ptr<bridge_interface_base> _if;
        bool _serve_stop = false;

        [[nodiscard]] r<std::string_view> register_command(std::string uuid, std::unique_ptr<command_base> cmd);

        [[nodiscard]] r<mlab::bin_data> remote_invoke(std::string_view uuid, mlab::bin_data const &body);

        [[nodiscard]] r<mlab::bin_data> command_response(mlab::bin_data payload) const;

        [[nodiscard]] r<mlab::bin_data> local_invoke(mlab::bin_data const &packed_cmd) const;

        [[nodiscard]] r<mlab::bin_data> local_invoke(std::string_view uuid, mlab::bin_stream &s) const;

    public:
        bridge() = default;

        explicit bridge(std::unique_ptr<bridge_interface_base> if_);

        bridge(bridge const &) = delete;
        bridge &operator=(bridge const &) = delete;

        bridge(bridge &&) = default;
        bridge &operator=(bridge &&) = default;

        template <class R, class T, class... Args>
        r<std::string_view> register_command(R (T::*method)(Args...), T &handler, std::string uuid = "");

        template <class R, class T, class... Args>
        r<std::string_view> register_command(R (T::*method)(Args...) const, T const &handler, std::string uuid = "");

        [[nodiscard]] bool contains(std::string_view uuid) const;

        /**
         * Will return @ref error::invalid_argument if multiple uuids match the signature.
         * Will return @ref error::mismatching_signature if none is found.
         */
        [[nodiscard]] r<std::string_view> lookup_uuid(std::string_view signature) const;

        template <class R, class T, class... Args>
        [[nodiscard]] r<std::string_view> lookup_uuid(R (T::*method)(Args...)) const;

        template <class R, class T, class... Args>
        [[nodiscard]] r<std::string_view> lookup_uuid(R (T::*method)(Args...) const) const;

        [[nodiscard]] std::string_view get_signature(std::string_view uuid) const;

        [[nodiscard]] r<std::string> remote_get_signature(std::string_view uuid) const;

        template <class R, class T, class... Args>
        [[nodiscard]] r<> remote_supports(R (T::*method)(Args...) const, std::string_view uuid = "") const;

        template <class R, class T, class... Args>
        [[nodiscard]] r<> remote_supports(R (T::*method)(Args...), std::string_view uuid = "") const;

        template <class R, class T, class... Args>
        [[nodiscard]] result_wrap_return<R> remote_invoke_unique(R (T::*method)(Args...) const, Args... args);

        template <class R, class T, class... Args>
        [[nodiscard]] result_wrap_return<R> remote_invoke_unique(R (T::*method)(Args...), Args... args);

        template <class R, class T, class... Args>
        [[nodiscard]] result_wrap_return<R> remote_invoke(R (T::*)(Args...) const, std::string_view uuid, Args... args);

        template <class R, class T, class... Args>
        [[nodiscard]] result_wrap_return<R> remote_invoke(R (T::*)(Args...), std::string_view uuid, Args... args);

        r<> serve_loop();

        void serve_stop();
    };

}// namespace ka::rpc

namespace pn532::p2p {
    struct target;
    struct initiator;
}// namespace pn532::p2p

namespace ka::p2p {

    enum struct bridge_last_action {
        command,
        response
    };

    class p2p_bridge_interface_base : public ka::rpc::bridge_interface_base {
        bridge_last_action _last_action = bridge_last_action::response;

    protected:
        [[nodiscard]] virtual ka::rpc::r<> send_command(mlab::bin_data data) = 0;
        [[nodiscard]] virtual ka::rpc::r<> send_response(mlab::bin_data data) = 0;
        [[nodiscard]] virtual ka::rpc::r<mlab::bin_data> receive_command() = 0;
        [[nodiscard]] virtual ka::rpc::r<mlab::bin_data> receive_response() = 0;

    public:
        p2p_bridge_interface_base() = default;

        [[nodiscard]] ka::rpc::r<mlab::bin_data> receive() final;
        [[nodiscard]] ka::rpc::r<> send(mlab::bin_data data) final;
    };

    class target_bridge_interface : public p2p_bridge_interface_base {
        std::shared_ptr<pn532::p2p::target> _tgt;

        [[nodiscard]] ka::rpc::r<> send_command(mlab::bin_data data) final;
        [[nodiscard]] ka::rpc::r<> send_response(mlab::bin_data data) final;
        [[nodiscard]] ka::rpc::r<mlab::bin_data> receive_command() final;
        [[nodiscard]] ka::rpc::r<mlab::bin_data> receive_response() final;

    public:
        explicit target_bridge_interface(std::shared_ptr<pn532::p2p::target> tgt);
    };

    class initiator_bridge_interface : public p2p_bridge_interface_base {
        std::shared_ptr<pn532::p2p::initiator> _ini;

        [[nodiscard]] ka::rpc::r<> send_command(mlab::bin_data data) final;
        [[nodiscard]] ka::rpc::r<> send_response(mlab::bin_data data) final;
        [[nodiscard]] ka::rpc::r<mlab::bin_data> receive_command() final;
        [[nodiscard]] ka::rpc::r<mlab::bin_data> receive_response() final;

    public:
        explicit initiator_bridge_interface(std::shared_ptr<pn532::p2p::initiator> ini);
    };

}// namespace ka::p2p

namespace ka::rpc {

    template <>
    struct use_default_serialization<bool> : std::true_type {};

    template <mlab::is_byte_enum T, std::size_t N>
    struct use_default_serialization<std::array<T, N>> : std::true_type {};

    template <std::size_t N>
    struct use_default_serialization<std::array<std::uint8_t, N>> : std::true_type {};


    template <class T>
    void serializer<T>::serialize(mlab::bin_data &bd, T const &t) {
        if constexpr (std::is_arithmetic_v<T>) {
            bd << mlab::lsb_auto << t;
        } else if constexpr (std::is_same_v<T, std::string_view> or std::is_same_v<T, std::string>) {
            bd << mlab::length_encoded << t;
        } else if constexpr (std::is_same_v<T, bool>) {
            bd << t;
        } else {
            static_assert(use_default_serialization<T>::value, "I do not know how to encode this type!");
            static_assert(mlab::is_injectable<T>, "You marked this type for using default serialization, but it's not injectable.");
            bd << t;
        }
    }

    template <class T>
    auto serializer<T>::deserialize(mlab::bin_stream &s) {
        if constexpr (std::is_arithmetic_v<T>) {
            T retval{};
            s >> mlab::lsb_auto >> retval;
            return retval;
        } else if constexpr (std::is_same_v<T, std::string_view> or std::is_same_v<T, std::string>) {
            std::string retval{};
            s >> mlab::length_encoded >> retval;
            return retval;
        } else if constexpr (std::is_same_v<T, bool>) {
            bool b = false;
            s >> b;
            return b;
        } else {
            static_assert(use_default_serialization<T>::value, "I do not know how to encode this type!");
            static_assert(mlab::is_extractable<T>, "You marked this type for using default serialization, but it's not extractable.");
            T retval{};
            s >> retval;
            return retval;
        }
    }

    template <class... Args>
    std::optional<deserialized_args_tuple_t<Args...>> deserialize(mlab::bin_stream &s) {
        auto retval = deserialized_args_tuple_t<Args...>{serializer<std::decay_t<Args>>::deserialize(s)...};
        if (s.bad() or not s.eof()) {
            return std::nullopt;
        }
        return retval;
    }

    template <class... Args>
    mlab::bin_data serialize(Args... args) {
        mlab::bin_data bd;
        (serializer<std::decay_t<Args>>::serialize(bd, args), ...);
        return bd;
    }

    template <class R, class T, class... Args>
    std::string signature_of(R (T::*)(Args...)) {
        return mlab::type_name<R (T::*)(Args...)>();
    }

    template <class R, class T, class... Args>
    std::string signature_of(R (T::*)(Args...) const) {
        return mlab::type_name<R (T::*)(Args...) const>();
    }

    template <class R, class T, class... Args>
    template <std::size_t... Is>
    r<mlab::bin_data> templated_command<R, T, Args...>::invoke_with_tuple(std::index_sequence<Is...>, deserialized_args_tuple_t<Args...> t) {
        if constexpr (std::is_void_v<R>) {
            ka::target_method<R, T, Args...>::operator()(std::get<Is>(t)...);
            return mlab::bin_data{};
        } else {
            return serialize<R>(ka::target_method<R, T, Args...>::operator()(std::get<Is>(t)...));
        }
    }

    template <class R, class T, class... Args>
    templated_command<R, T, Args...>::templated_command(fn_ptr_t method, target_ptr_t ptr)
        : command_base{signature_of(method)},
          ka::target_method<R, T, Args...>{ptr, method} {}

    template <class R, class T, class... Args>
    r<mlab::bin_data> templated_command<R, T, Args...>::command_response(mlab::bin_stream &s) {
        if constexpr (sizeof...(Args) == 0) {
            if (s.eof()) {
                return invoke_with_tuple(std::index_sequence_for<Args...>{}, std::tuple<>{});
            }
        } else {
            if (auto args_tuple = deserialize<Args...>(s); args_tuple) {
                return invoke_with_tuple(std::index_sequence_for<Args...>{}, std::move(*args_tuple));
            }
        }
        return error::parsing_error;
    }

    template <class R, class T, class... Args>
    r<std::string_view> bridge::register_command(R (T::*method)(Args...), T &handler, std::string uuid) {
        return register_command(uuid.empty() ? signature_of(method) : std::move(uuid),
                                std::make_unique<templated_command<R, T, Args...>>(method, &handler));
    }

    template <class R, class T, class... Args>
    r<std::string_view> bridge::register_command(R (T::*method)(Args...) const, T const &handler, std::string uuid) {
        return register_command(uuid.empty() ? signature_of(method) : std::move(uuid),
                                std::make_unique<templated_command<R, const T, Args...>>(method, &handler));
    }

    template <class R, class T, class... Args>
    r<std::string_view> bridge::lookup_uuid(R (T::*method)(Args...)) const {
        return lookup_uuid(signature_of(method));
    }

    template <class R, class T, class... Args>
    r<std::string_view> bridge::lookup_uuid(R (T::*method)(Args...) const) const {
        return lookup_uuid(signature_of(method));
    }

    template <class R, class T, class... Args>
    r<> bridge::remote_supports(R (T::*method)(Args...) const, std::string_view uuid) const {
        const auto sign = signature_of(method);
        if (const auto r = remote_get_signature(uuid.empty() ? sign : std::string{uuid}); not r) {
            return r.error();
        } else if (sign != *r) {
            return error::mismatching_signature;
        }
        return mlab::result_success;
    }

    template <class R, class T, class... Args>
    r<> bridge::remote_supports(R (T::*method)(Args...), std::string_view uuid) const {
        const auto sign = signature_of(method);
        if (const auto r = remote_get_signature(uuid.empty() ? sign : std::string{uuid}); not r) {
            return r.error();
        } else if (sign != *r) {
            return error::mismatching_signature;
        }
        return mlab::result_success;
    }


    template <class R, class T, class... Args>
    result_wrap_return<R> bridge::remote_invoke_unique(R (T::*method)(Args...) const, Args... args) {
        if (const auto r = lookup_uuid(method); not r) {
            return r.error();
        } else {
            return remote_invoke(method, *r, std::forward<Args>(args)...);
        }
    }

    template <class R, class T, class... Args>
    result_wrap_return<R> bridge::remote_invoke_unique(R (T::*method)(Args...), Args... args) {
        if (const auto r = lookup_uuid(method); not r) {
            return r.error();
        } else {
            return remote_invoke(method, *r, std::forward<Args>(args)...);
        }
    }


    template <class R, class T, class... Args>
    result_wrap_return<R> bridge::remote_invoke(R (T::*)(Args...) const, std::string_view uuid, Args... args) {
        mlab::bin_data serialized_args;
        if constexpr (sizeof...(Args) > 0) {
            serialized_args = serialize<Args...>(std::forward<Args>(args)...);
        }
        if (const auto r_invoke = remote_invoke(uuid, serialized_args); r_invoke) {
            if constexpr (std::is_void_v<R>) {
                if (not r_invoke->empty()) {
                    return error::parsing_error;
                }
                return mlab::result_success;
            } else {
                mlab::bin_stream s{*r_invoke};
                if (const auto r = deserialize<R>(s); r) {
                    return std::move(std::get<0>(*r));
                } else {
                    return error::parsing_error;
                }
            }
        } else {
            return r_invoke.error();
        }
    }

    template <class R, class T, class... Args>
    result_wrap_return<R> bridge::remote_invoke(R (T::*)(Args...), std::string_view uuid, Args... args) {
        mlab::bin_data serialized_args;
        if constexpr (sizeof...(Args) > 0) {
            serialized_args = serialize<Args...>(std::forward<Args>(args)...);
        }
        if (const auto r_invoke = remote_invoke(uuid, serialized_args); r_invoke) {
            if constexpr (std::is_void_v<R>) {
                if (not r_invoke->empty()) {
                    return error::parsing_error;
                }
                return mlab::result_success;
            } else {
                mlab::bin_stream s{*r_invoke};
                if (const auto r = deserialize<R>(s); r) {
                    return std::move(std::get<0>(*r));
                } else {
                    return error::parsing_error;
                }
            }
        } else {
            return r_invoke.error();
        }
    }
}// namespace ka::rpc

#endif//KEYCARD_ACCESS_RPC_HPP
