//
// Created by spak on 6/14/23.
//

#ifndef KEYCARD_ACCESS_CONSOLE_HPP
#define KEYCARD_ACCESS_CONSOLE_HPP

#include <functional>
#include <ka/misc.hpp>
#include <mlab/result.hpp>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace ka {
    class console {
    public:
        console();

        console(console const &) = delete;
        console(console &&) noexcept = delete;

        console &operator=(console const &) = delete;
        console &operator=(console &&) noexcept = delete;

        [[nodiscard]] std::string read_line(std::string_view prompt = "> ") const;

        ~console();
    };

    namespace cmd {
        enum struct argument_type {
            regular,
            positional,
            flag
        };

        enum struct error {
            parse,
            missing,
            unrecognized,
            help_invoked
        };

        template <class... Args>
        using r = mlab::result<error, Args...>;

        struct argument;

        using value_argument_map = std::vector<std::pair<std::reference_wrapper<const argument>, std::optional<std::string_view>>>;

        struct argument {
            argument_type type = argument_type::regular;

            /**
             * A string representing the argument. The meaning varies depending on the type of argument:
             *  - @ref argument_type::regular this is the string that follows "--" in the parameter, e.g. if the @ref token_main is
             *    "regular", then this parameter is identified by the prefix "--regular <value>".
             *  - @ref argument_type::positional this is the name of the parameter that appears in the help string.
             *  - @ref argument_type::flag like @ref argument_type::regular, this identifies the flag option that sets the true value, e.g.
             *    "do-set-to-true" sets the flag to true when "--do-set-to-true" is present in the argument list.
             *    Conversely, the option "--no-do-set-to-true" will set the argument to false.
             */
            std::string_view token_main;

            /**
             * An alternative string representing the argument. The meaning varies depending on the type of argument:
             *  - @ref argument_type::regular this is the string that follows "-" in the parameter, e.g. if the @ref token_alternate is
             *    "r", then this parameter is identified by the prefix "-r <value>".
             *  - @ref argument_type::positional this is unused.
             *  - @ref argument_type::flag like @ref argument_type::regular, this identifies the short flag option that sets the true value, e.g.
             *    "d" sets the flag to true when "-d" is present in the argument list.
             *    Conversely, the option "-nd" will set the argument to false.
             */
            std::string_view token_alternate;

            [[nodiscard]] static r<value_argument_map> map_values(std::vector<std::string_view> const &values, std::vector<std::reference_wrapper<const argument>> const &arguments);

            [[nodiscard]] std::string signature_string(std::string_view value_marker) const;
            [[nodiscard]] std::string help_string(std::string_view type_info, std::string_view default_value) const;
        };

        struct positional {
            std::string_view name;

            explicit positional(std::string_view name_) : name{name_} {}
        };

        struct flag {
            std::string_view token_main;
            std::string_view token_alternate;
            std::optional<bool> default_value;

            inline explicit flag(std::string_view token_main_, std::optional<bool> default_value_ = std::nullopt);

            inline explicit flag(std::string_view token_main_, std::string_view token_alternate_, std::optional<bool> default_value_ = std::nullopt);
        };

        template <class T = void>
        struct regular {
            std::string_view token_main;
            std::string_view token_alternate;
            std::optional<T> default_value;

            inline explicit regular(std::string_view token_main_, std::optional<T> default_value_ = std::nullopt);

            inline explicit regular(std::string_view token_main_, std::string_view token_alternate_, std::optional<T> default_value_ = std::nullopt);
        };

        template <>
        struct regular<void> {
            std::string_view token_main;
            std::string_view token_alternate;

            inline explicit regular(std::string_view token_main_);

            inline explicit regular(std::string_view token_main_, std::string_view token_alternate_);
        };

        template <class T>
        struct typed_argument : argument {
            using value_type = T;

            std::optional<T> default_value = std::nullopt;

            [[nodiscard]] r<T> parse(std::optional<std::string_view> value) const;

            template <class U = T>
            typed_argument(std::enable_if_t<std::is_same_v<U, bool>, flag> flag_);
            typed_argument(positional pos_);
            typed_argument(regular<void> reg_);
            typed_argument(regular<T> reg_);
            typed_argument(std::string_view token_main_);
            typed_argument(std::string_view token_main_, T default_value_);
            typed_argument(std::string_view token_main_, std::string_view token_alternate_);
            typed_argument(std::string_view token_main_, std::string_view token_alternate_, T default_value_);

            [[nodiscard]] std::string help_string() const;
            [[nodiscard]] std::string signature_string() const;
        };

        template <class T>
        struct parser {
            [[nodiscard]] static r<T> parse(std::string_view value);
        };

        namespace traits {
            template <class T>
            struct is_typed_argument;

            template <class T, class... Args>
            struct types_to_typed_argument_tuple;
        }// namespace traits

        template <class T>
        concept is_typed_argument_v = traits::is_typed_argument<T>::value;

        /**
         * @tparam TArgs
         * @param targs
         * @param values
         * @return Given TArgs = typed_argument<T1>, ..., typed_argument<Tn>, returns r<T1, ..., Tn>.
         */
        template <is_typed_argument_v... TArgs>
        [[nodiscard]] auto parse_from_string(std::tuple<TArgs...> const &targs, std::vector<std::string_view> const &values);

        struct command_base {
            std::string_view name;

            explicit command_base(std::string_view name_) : name{name_} {}

            [[nodiscard]] virtual r<> parse_and_invoke(std::vector<std::string_view> const &values) = 0;
            [[nodiscard]] virtual std::string signature() const = 0;
            [[nodiscard]] virtual std::string help() const = 0;

            ~command_base() = default;
        };

        namespace util {
            struct void_struct;
            template <class R, class T, class... Args>
            struct target_method;
        }// namespace util

        template <class R, class T = util::void_struct, class... Args>
        struct command final : command_base, traits::types_to_typed_argument_tuple<Args...>::type {
            util::target_method<R, T, Args...> tm;

            using traits::types_to_typed_argument_tuple<Args...>::type::type;

            explicit command(std::string_view name, T *obj_, R (T::*fn_)(Args...), traits::types_to_typed_argument_tuple<Args...>::type arg_seq);

            explicit command(std::string_view name, R (*fn_)(Args...), traits::types_to_typed_argument_tuple<Args...>::type arg_seq);

            [[nodiscard]] auto parse(std::vector<std::string_view> const &values) const;

            R invoke_with_tuple(std::tuple<Args...> &&tpl);

            R operator()(Args... args);

            [[nodiscard]] r<> parse_and_invoke(std::vector<std::string_view> const &values) override;

            [[nodiscard]] std::string signature() const override;
            [[nodiscard]] std::string help() const override;
        };

        class shell {
            std::vector<std::unique_ptr<command_base>> _cmds;

            static void linenoise_completion(const char *typed, linenoiseCompletions *lc);
            static char *linenoise_hints(const char *typed, int *color, int *bold);
            static void linenoise_free_hints(void *data);

            shell() = default;

        public:
            template <class R, class... Args>
            void register_command(std::string_view name, R (*fn)(Args...), traits::types_to_typed_argument_tuple<Args...>::type arg_seq);

            template <class R, class T, class... Args>
            void register_command(std::string_view name, T &obj, R (T::*fn)(Args...), traits::types_to_typed_argument_tuple<Args...>::type arg_seq);

            void repl(console &c) const;

            static shell &instance();
        };

    }// namespace cmd
}// namespace ka

namespace ka::cmd {

    namespace traits {
        template <class T, class... Args>
        struct types_to_result_tuple {
            using type = decltype(std::tuple_cat(std::declval<std::tuple<r<T>>>(), std::declval<typename types_to_result_tuple<Args...>::type>()));
        };

        template <class T>
        struct types_to_result_tuple<T> {
            using type = std::tuple<r<T>>;
        };

        static_assert(std::is_same_v<types_to_result_tuple<int>::type, std::tuple<r<int>>>);
        static_assert(std::is_same_v<types_to_result_tuple<int, float>::type, std::tuple<r<int>, r<float>>>);

        template <class T, class... Args>
        struct types_to_typed_argument_tuple {
            using type = decltype(std::tuple_cat(std::declval<std::tuple<typed_argument<T>>>(), std::declval<typename types_to_typed_argument_tuple<Args...>::type>()));
        };

        template <class T>
        struct types_to_typed_argument_tuple<T> {
            using type = std::tuple<typed_argument<T>>;
        };

        static_assert(std::is_same_v<types_to_typed_argument_tuple<int>::type, std::tuple<typed_argument<int>>>);
        static_assert(std::is_same_v<types_to_typed_argument_tuple<int, float>::type, std::tuple<typed_argument<int>, typed_argument<float>>>);

        template <class T>
        struct is_typed_argument : std::false_type {};

        template <class T>
        struct is_typed_argument<typed_argument<T>> : std::true_type {};

        template <std::size_t N>
        struct fixed_size_string {
            char data[N];

            [[nodiscard]] std::size_t constexpr size() const {
                return N;
            }

            /**
                 * @note It's possible to automatically deduct the size when passing string literals as follows:
                 * @code
                 *  constexpr fixed_size_string(const char s[N]);
                 * @endcode
                 */
            constexpr fixed_size_string(const char *s) {
                std::size_t i = 0;
                for (; i < N - 1; ++i) {
                    if (s[i] == '\0') {
                        break;
                    }
                    data[i] = s[i];
                }
                for (; i < N; ++i) {
                    data[i] = '\0';
                }
            }

            [[nodiscard]] constexpr std::size_t find(char c) const {
                return std::find(std::begin(data), std::end(data), c) - std::begin(data);
            }

            [[nodiscard]] constexpr std::size_t find_any(std::initializer_list<char> cs) const {
                return std::find_first_of(std::begin(data), std::end(data), std::begin(cs), std::end(cs)) - std::begin(data);
            }

            template <std::size_t Start, std::size_t End>
            [[nodiscard]] constexpr auto substr() const {
                static_assert(Start < End and End <= N);
                auto retval = fixed_size_string<End - Start + 1>{&data[Start]};
                retval.data[End - Start] = '\0';
                return retval;
            }
        };

        template <class T, std::size_t BufSize = 256>
        [[nodiscard]] constexpr auto type_name() {
            constexpr auto method_name = fixed_size_string<BufSize>{__PRETTY_FUNCTION__};
            constexpr auto equal_pos = method_name.find('=');
            constexpr auto end_pos = method_name.find_any({';', ',', ']'});
            if constexpr (end_pos > equal_pos + 2) {
                return method_name.template substr<equal_pos + 2, end_pos>();
            } else {
                return fixed_size_string<1>{""};
            }
        }

        template <ka::cmd::is_typed_argument_v T, ka::cmd::is_typed_argument_v... Args>
        struct typed_args_to_result_tuple {
            using type = typename mlab::concat_result_t<r<typename T::value_type>, typename typed_args_to_result_tuple<Args...>::type>;
        };

        template <ka::cmd::is_typed_argument_v T>
        struct typed_args_to_result_tuple<T> {
            using type = r<typename T::value_type>;
        };

        static_assert(std::is_same_v<typed_args_to_result_tuple<typed_argument<int>>::type, r<int>>);
        static_assert(std::is_same_v<typed_args_to_result_tuple<typed_argument<int>, typed_argument<float>>::type, r<int, float>>);
    }// namespace traits

    namespace util {
        struct void_struct {
            /**
                 * @note This is needed because to use automated template argument resolution, we need to have in the cctor of
                 * @ref command all the parameters available; this means we must be able to spell T::*method, and that cannot
                 * be done with anything that is not a struct type.
                 */
        };

        template <class R, class T, class... Args>
        struct target_method {
            using target_ptr_t = T *;
            using fn_ptr_t = R (T::*)(Args...);

            target_ptr_t target;
            fn_ptr_t method;

            target_method(target_ptr_t target_, fn_ptr_t method_) : target{target_}, method{method_} {}

            auto invoke_with_tuple(std::tuple<Args...> &&args) {
                return ((*target).*method)(std::forward<Args>(std::get<Args>(args))...);
            }

            auto operator()(Args... args) {
                return ((*target).*method)(std::forward<Args>(args)...);
            }
        };

        template <class R, class... Args>
        struct target_method<R, void_struct, Args...> {
            using fn_ptr_t = R (*)(Args...);

            fn_ptr_t method;

            explicit target_method(fn_ptr_t method_) : method{method_} {}

            auto invoke_with_tuple(std::tuple<Args...> &&args) {
                return (*method)(std::forward<Args>(std::get<Args>(args))...);
            }

            auto operator()(Args... args) {
                return method(std::forward<Args>(args)...);
            }
        };
    }// namespace util

    flag::flag(std::string_view token_main_, std::optional<bool> default_value_)
        : token_main{token_main_}, token_alternate{}, default_value{default_value_} {}

    flag::flag(std::string_view token_main_, std::string_view token_alternate_, std::optional<bool> default_value_)
        : token_main{token_main_}, token_alternate{token_alternate_}, default_value{default_value_} {}

    template <class T>
    regular<T>::regular(std::string_view token_main_, std::optional<T> default_value_)
        : token_main{token_main_}, token_alternate{}, default_value{default_value_} {}

    template <class T>
    regular<T>::regular(std::string_view token_main_, std::string_view token_alternate_, std::optional<T> default_value_)
        : token_main{token_main_}, token_alternate{token_alternate_}, default_value{default_value_} {}

    regular<void>::regular(std::string_view token_main_)
        : token_main{token_main_}, token_alternate{} {}

    regular<void>::regular(std::string_view token_main_, std::string_view token_alternate_)
        : token_main{token_main_}, token_alternate{token_alternate_} {}

    template <class T>
    template <class U>
    typed_argument<T>::typed_argument(std::enable_if_t<std::is_same_v<U, bool>, flag> flag_)
        : argument{argument_type::flag, flag_.token_main, flag_.token_alternate}, default_value{flag_.default_value} {}

    template <class T>
    typed_argument<T>::typed_argument(positional pos_)
        : argument{argument_type::positional, pos_.name, {}}, default_value{} {}

    template <class T>
    typed_argument<T>::typed_argument(regular<void> reg_)
        : argument{argument_type::regular, reg_.token_main, reg_.token_alternate}, default_value{} {}

    template <class T>
    typed_argument<T>::typed_argument(regular<T> reg_)
        : argument{argument_type::regular, reg_.token_main, reg_.token_alternate}, default_value{reg_.default_value} {}

    template <class T>
    typed_argument<T>::typed_argument(std::string_view token_main_)
        : argument{argument_type::regular, token_main_, {}}, default_value{std::nullopt} {}

    template <class T>
    typed_argument<T>::typed_argument(std::string_view token_main_, T default_value_)
        : argument{argument_type::regular, token_main_, {}}, default_value{default_value_} {}

    template <class T>
    typed_argument<T>::typed_argument(std::string_view token_main_, std::string_view token_alternate_)
        : argument{argument_type::regular, token_main_, token_alternate_}, default_value{std::nullopt} {}

    template <class T>
    typed_argument<T>::typed_argument(std::string_view token_main_, std::string_view token_alternate_, T default_value_)
        : argument{argument_type::regular, token_main_, token_alternate_}, default_value{default_value_} {}

    template <class T>
    std::string typed_argument<T>::help_string() const {
        return argument::help_string(traits::type_name<T>().data, default_value ? std::to_string(*default_value) : "");
    }

    template <class T>
    std::string typed_argument<T>::signature_string() const {
        if (default_value) {
            return argument::signature_string(std::to_string(*default_value));
        } else {
            return argument::signature_string(traits::type_name<T>().data);
        }
    }

    template <class T>
    r<T> typed_argument<T>::parse(std::optional<std::string_view> value) const {
        if (value == std::nullopt) {
            if (type == argument_type::positional or default_value == std::nullopt) {
                ESP_LOGE("KA", "Missing value for argument %s.", token_main.data());
                return error::missing;
            }
            return *default_value;
        }
        if constexpr (std::is_same_v<T, bool>) {
            if (type == argument_type::flag) {
                if (value->starts_with("--no-") and value->substr(5) == token_main) {
                    return false;
                }
                if (value->starts_with("--") and value->substr(2) == token_main) {
                    return true;
                }
                if (value->starts_with('-') and value->substr(1) == token_alternate) {
                    return true;
                }
                if (value->starts_with("-n") and value->substr(2) == token_alternate) {
                    return false;
                }
                ESP_LOGE("KA", "Invalid flag expression %s for argument %s.", value->data(), token_main.data());
                return error::unrecognized;
            }
        }
        auto r = parser<T>::parse(*value);
        if (not r) {
            ESP_LOGE("KA", "Invalid value %s for %s.", value->data(), __PRETTY_FUNCTION__);
        }
        return r;
    }

    template <class T>
    r<T> parser<T>::parse(std::string_view value) {
        // We need the c_str
        const std::string stored_str{value};
        auto const *p = stored_str.c_str();

        if constexpr (std::is_same_v<T, int> or std::is_same_v<T, long>) {
            char *p_end{};
            if (const auto r = std::strtol(p, &p_end, 10); p_end != p) {
                if constexpr (std::is_same_v<T, int>) {
                    return static_cast<int>(r);
                } else {
                    return r;
                }
            }
        } else if constexpr (std::is_same_v<T, unsigned int> or std::is_same_v<T, unsigned long>) {
            char *p_end{};
            if (const auto r = std::strtoul(p, &p_end, 10); p_end != p) {
                if constexpr (std::is_same_v<T, unsigned int>) {
                    return static_cast<unsigned int>(r);
                } else {
                    return r;
                }
            }
        } else if constexpr (std::is_same_v<T, long long>) {
            char *p_end{};
            if (const auto r = std::strtoll(p, &p_end, 10); p_end != p) {
                return r;
            }
        } else if constexpr (std::is_same_v<T, unsigned long long>) {
            char *p_end{};
            if (const auto r = std::strtoull(p, &p_end, 10); p_end != p) {
                return r;
            }
        } else if constexpr (std::is_same_v<T, float>) {
            char *p_end{};
            if (const auto r = std::strtof(p, &p_end); p_end != p) {
                return r;
            }
        } else if constexpr (std::is_same_v<T, double>) {
            char *p_end{};
            if (const auto r = std::strtod(p, &p_end); p_end != p) {
                return r;
            }
        } else if constexpr (std::is_same_v<T, std::string>) {
            return std::string{value};
        } else if constexpr (std::is_same_v<T, bool>) {
            std::string v{p};
            std::transform(std::begin(v), std::end(v), std::begin(v), ::tolower);
            if (v == "true" or v == "1" or v == "y" or v == "yes") {
                return true;
            } else if (v == "false" or v == "0" or v == "n" or v == "no") {
                return false;
            }
        }
        return error::parse;
    }

    template <class R, class T, class... Args>
    command<R, T, Args...>::command(std::string_view name, T *obj_, R (T::*fn_)(Args...), traits::types_to_typed_argument_tuple<Args...>::type arg_seq)
        : command_base{name}, traits::types_to_typed_argument_tuple<Args...>::type{std::move(arg_seq)},
          tm{obj_, fn_} {}

    template <class R, class T, class... Args>
    command<R, T, Args...>::command(std::string_view name, R (*fn_)(Args...), traits::types_to_typed_argument_tuple<Args...>::type arg_seq)
        : command_base{name}, traits::types_to_typed_argument_tuple<Args...>::type{std::move(arg_seq)},
          tm{fn_} {}


    template <class R, class T, class... Args>
    auto command<R, T, Args...>::parse(std::vector<std::string_view> const &values) const {
        return parse_from_string(*this, values);
    }

    template <class R, class T, class... Args>
    R command<R, T, Args...>::invoke_with_tuple(std::tuple<Args...> &&tpl) {
        return tm.invoke_with_tuple(std::move(tpl));
    }

    template <class R, class T, class... Args>
    R command<R, T, Args...>::operator()(Args... args) {
        return tm(std::forward<Args>(args)...);
    }

    template <class R, class T, class... Args>
    r<> command<R, T, Args...>::parse_and_invoke(std::vector<std::string_view> const &values) {
        if (auto r_args = parse(values); r_args) {
            invoke_with_tuple(std::move(*r_args));
            return mlab::result_success;
        } else {
            return r_args.error();
        }
    }

    namespace util {
        template <std::size_t StartIdx = 0, ka::cmd::is_typed_argument_v... TArgs>
        constexpr auto parse_tail(std::tuple<TArgs...> const &targs, value_argument_map const &vmap) {
            auto ith_r = std::get<StartIdx>(targs).parse(vmap[StartIdx].second);
            if constexpr (StartIdx >= sizeof...(TArgs) - 1) {
                return ith_r;
            } else {
                return mlab::concat_result(ith_r, parse_tail<StartIdx + 1, TArgs...>(targs, vmap));
            }
        }

        static_assert(std::is_same_v<
                      decltype(parse_tail(std::declval<std::tuple<typed_argument<int>, typed_argument<float>>>(), std::declval<value_argument_map>())),
                      r<int, float>>);
        static_assert(std::is_same_v<
                      decltype(parse_tail(std::declval<std::tuple<typed_argument<int>, typed_argument<float>, typed_argument<std::string>>>(), std::declval<value_argument_map>())),
                      r<int, float, std::string>>);

    }// namespace util

    template <is_typed_argument_v... TArgs>
    auto parse_from_string(std::tuple<TArgs...> const &targs, std::vector<std::string_view> const &values) {
        using result_v = traits::typed_args_to_result_tuple<TArgs...>::type;
        if (auto r_map = argument::map_values(values, {std::get<TArgs>(targs)...}); r_map) {
            return util::parse_tail<0, TArgs...>(targs, std::move(*r_map));
        } else {
            return result_v{r_map.error()};
        };
    }

    static_assert(std::is_same_v<
                  decltype(parse_from_string(std::declval<std::tuple<typed_argument<int>, typed_argument<float>>>(), std::declval<std::vector<std::string_view>>())),
                  r<int, float>>);
    static_assert(std::is_same_v<
                  decltype(parse_from_string(std::declval<std::tuple<typed_argument<int>, typed_argument<float>, typed_argument<std::string>>>(), std::declval<std::vector<std::string_view>>())),
                  r<int, float, std::string>>);

    template <class R, class T, class... Args>
    std::string command<R, T, Args...>::signature() const {
        std::vector<std::string> strs;
        strs.reserve(sizeof...(Args) + 1);
        strs.emplace_back("");
        std::apply([&](auto const &...targs) {
            (strs.push_back(targs.signature_string()), ...);
        },
                   static_cast<traits::types_to_typed_argument_tuple<Args...>::type const &>(*this));
        return concatenate_strings(strs, " ");
    }

    template <class R, class T, class... Args>
    std::string command<R, T, Args...>::help() const {
        std::vector<std::string> strs;
        strs.reserve(sizeof...(Args) + 1);
        strs.push_back(std::string{name});
        std::apply([&](auto const &...targs) {
            (strs.push_back(targs.help_string()), ...);
        },
                   static_cast<traits::types_to_typed_argument_tuple<Args...>::type const &>(*this));
        return concatenate_strings(strs, "\n    ");
    }

    template <class R, class... Args>
    void shell::register_command(std::string_view name, R (*fn)(Args...), traits::types_to_typed_argument_tuple<Args...>::type arg_seq) {
        _cmds.push_back(std::make_unique<command<R, util::void_struct, Args...>>(name, fn, std::move(arg_seq)));
    }

    template <class R, class T, class... Args>
    void shell::register_command(std::string_view name, T &obj, R (T::*fn)(Args...), traits::types_to_typed_argument_tuple<Args...>::type arg_seq) {
        _cmds.push_back(std::make_unique<command<R, T, Args...>>(name, &obj, fn, std::move(arg_seq)));
    }

}// namespace ka::cmd

#endif//KEYCARD_ACCESS_CONSOLE_HPP
