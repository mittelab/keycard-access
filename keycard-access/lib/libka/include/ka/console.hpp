//
// Created by spak on 6/14/23.
//

#ifndef KEYCARD_ACCESS_CONSOLE_HPP
#define KEYCARD_ACCESS_CONSOLE_HPP

#include <functional>
#include <ka/misc.hpp>
#include <mlab/result.hpp>
#include <mlab/strutils.hpp>
#include <mlab/type_name.hpp>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

struct linenoiseCompletions;

namespace ka {

    template <class Fn>
    concept prompt_parsing_function = requires(Fn &&fn) {
                                          bool(fn(std::declval<std::string>()));
                                          not std::is_void_v<decltype(*fn(std::declval<std::string>()))>;
                                      };

    class console {
        struct console_setup;
        std::shared_ptr<console_setup> _raii;

    public:
        console();
        [[nodiscard]] std::optional<std::string> read_line(std::string_view prompt = "> ") const;

        template <prompt_parsing_function Fn>
        [[nodiscard]] auto repeated_prompt(std::string_view prompt_desc, std::string_view prompt, bool allow_cancel, Fn &&parse);
    };

    namespace cmd_literals {
        inline auto operator""_pos(const char *name, std::size_t);
        inline auto operator""_flag(const char *name, std::size_t);
        inline auto operator""_arg(const char *name, std::size_t);
    }// namespace cmd_literals

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

        [[nodiscard]] const char *to_string(error e);

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
        struct parser {
            [[nodiscard]] static r<T> parse(std::string_view value);
            [[nodiscard]] static std::string to_string(T const &value);
            [[nodiscard]] static std::string type_description();
        };

        template <class T>
        concept parse_can_output = requires { std::is_void_v<T>; } or requires(T a) {
                                                                          { parser<T>::to_string(std::declval<T>()) } -> std::convertible_to<std::string>;
                                                                      };

        template <class T>
        concept parse_can_input = requires(T a) {
                                      { parser<T>::parse(std::string_view{}) } -> std::same_as<r<T>>;
                                  };

        template <class T>
        concept parsable = parse_can_input<T> and parse_can_output<T>;

        template <class T>
        struct parser<std::optional<T>> {
            [[nodiscard]] static std::string to_string(std::optional<T> const &value);
        };

        template <>
        struct parser<std::string> {
            [[nodiscard]] static inline r<std::string> parse(std::string_view value);
            [[nodiscard]] static inline std::string to_string(std::string const &value);
            [[nodiscard]] static inline std::string type_description();
        };

        template <>
        struct parser<std::string_view> {
            [[nodiscard]] static inline r<std::string_view> parse(std::string_view value);
            [[nodiscard]] static inline std::string to_string(std::string_view const &value);
            [[nodiscard]] static inline std::string type_description();
        };

        template <parsable T>
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

            template <class U = T>
            typed_argument(std::enable_if_t<not std::is_constructible_v<std::string_view, U>, std::string_view> token_main_, U default_value_);

            template <class U = T>
            typed_argument(std::enable_if_t<not std::is_constructible_v<std::string_view, U>, std::string_view> token_main_, std::string_view token_alternate_);

            typed_argument(std::string_view token_main_, std::string_view token_alternate_, T default_value_);

            [[nodiscard]] std::string help_string() const;
            [[nodiscard]] std::string signature_string() const;
        };

        template <class... Args>
        using typed_arguments_tuple_t = std::tuple<typed_argument<Args>...>;

        struct command_base {
            std::string_view name;

            explicit command_base(std::string_view name_) : name{name_} {}

            [[nodiscard]] virtual r<std::string> parse_and_invoke(std::vector<std::string_view> const &values) = 0;
            [[nodiscard]] virtual std::string signature() const = 0;
            [[nodiscard]] virtual std::string help() const = 0;

            virtual ~command_base() = default;
        };

        template <parse_can_output R, class T = void_struct, parsable... Args>
        struct command final : command_base, typed_arguments_tuple_t<Args...>, target_method<R, T, Args...> {

            explicit command(std::string_view name, T *obj_, R (T::*fn_)(Args...), typed_arguments_tuple_t<Args...> arg_seq);

            explicit command(std::string_view name, T *obj_, R (T::*fn_)(Args...) const, typed_arguments_tuple_t<Args...> arg_seq);

            explicit command(std::string_view name, R (*fn_)(Args...), typed_arguments_tuple_t<Args...> arg_seq);

            [[nodiscard]] r<Args...> parse(std::vector<std::string_view> const &values) const;

            using target_method<R, T, Args...>::operator();

            [[nodiscard]] r<std::string> parse_and_invoke(std::vector<std::string_view> const &values) override;

            [[nodiscard]] std::string signature() const override;

            [[nodiscard]] std::string help() const override;

        private:
            /**
             * @note These two methods are needed so we can unpack a tuple based on indices, not on types,
             * since we might have multiple occurrences of the same type within the tuple.
             */
            template <std::size_t... Is>
            R invoke(std::index_sequence<Is...>, r<Args...> args);

            template <std::size_t... Is>
            [[nodiscard]] r<Args...> parse(std::index_sequence<Is...>, std::vector<std::string_view> const &values) const;
        };

        class shell {
            std::vector<std::unique_ptr<command_base>> _cmds;

            struct activate_on_linenoise;

            static void linenoise_completion(const char *typed, linenoiseCompletions *lc);
            static char *linenoise_hints(const char *typed, int *color, int *bold);
            static void linenoise_free_hints(void *data);

            void help() const;

        public:
            shell() = default;

            template <class R, parsable... Args>
            void register_command(std::string_view name, R (*fn)(Args...), typed_arguments_tuple_t<Args...> arg_seq);

            template <class R = void, class T, parsable... Args>
            void register_command(std::string_view name, T &obj, R (T::*fn)(Args...), typed_arguments_tuple_t<Args...> arg_seq);

            template <class R = void, class T, parsable... Args>
            void register_command(std::string_view name, T const &obj, R (T::*fn)(Args...) const, typed_arguments_tuple_t<Args...> arg_seq);

            void register_help_command(std::string_view name = "help");

            void repl(console &c) const;
        };

    }// namespace cmd
}// namespace ka

namespace ka {


    template <prompt_parsing_function Fn>
    auto console::repeated_prompt(std::string_view prompt_desc, std::string_view prompt, bool allow_cancel, Fn &&parse) {
        using fn_retval_t = std::decay_t<decltype(*parse(std::declval<std::string>()))>;
        using retval_t = std::optional<fn_retval_t>;
        while (true) {
            if (not prompt_desc.empty()) {
                std::printf("%s\n", prompt_desc.data());
            }
            if (auto user_input = read_line(prompt); user_input) {
                if (auto parsed_object = parse(std::move(*user_input)); parsed_object) {
                    return retval_t{*parsed_object};
                }
            } else if (allow_cancel) {
                return retval_t{std::nullopt};
            }
        }
    }

    namespace cmd {

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

        template <parsable T>
        template <class U>
        typed_argument<T>::typed_argument(std::enable_if_t<std::is_same_v<U, bool>, flag> flag_)
            : argument{argument_type::flag, flag_.token_main, flag_.token_alternate}, default_value{flag_.default_value} {}

        template <parsable T>
        typed_argument<T>::typed_argument(positional pos_)
            : argument{argument_type::positional, pos_.name, {}}, default_value{} {}

        template <parsable T>
        typed_argument<T>::typed_argument(regular<void> reg_)
            : argument{argument_type::regular, reg_.token_main, reg_.token_alternate}, default_value{} {}

        template <parsable T>
        typed_argument<T>::typed_argument(regular<T> reg_)
            : argument{argument_type::regular, reg_.token_main, reg_.token_alternate}, default_value{reg_.default_value} {}

        template <parsable T>
        typed_argument<T>::typed_argument(std::string_view token_main_)
            : argument{argument_type::regular, token_main_, {}}, default_value{std::nullopt} {}

        template <parsable T>
        template <class U>
        typed_argument<T>::typed_argument(std::enable_if_t<not std::is_constructible_v<std::string_view, U>, std::string_view> token_main_, U default_value_)
            : argument{argument_type::regular, token_main_, {}}, default_value{default_value_} {}

        template <parsable T>
        template <class U>
        typed_argument<T>::typed_argument(std::enable_if_t<not std::is_constructible_v<std::string_view, U>, std::string_view> token_main_, std::string_view token_alternate_)
            : argument{argument_type::regular, token_main_, token_alternate_}, default_value{std::nullopt} {}

        template <parsable T>
        typed_argument<T>::typed_argument(std::string_view token_main_, std::string_view token_alternate_, T default_value_)
            : argument{argument_type::regular, token_main_, token_alternate_}, default_value{default_value_} {}

        template <parsable T>
        std::string typed_argument<T>::help_string() const {
            if constexpr (std::is_same_v<T, bool>) {
                if (default_value and type == argument_type::flag) {
                    return argument::help_string(parser<T>::type_description(), *default_value ? "Y" : "N");
                }
            }
            return argument::help_string(parser<T>::type_description(), default_value ? parser<T>::to_string(*default_value) : "");
        }

        template <parsable T>
        std::string typed_argument<T>::signature_string() const {
            if (default_value) {
                if constexpr (std::is_same_v<T, bool>) {
                    if (type == argument_type::flag) {
                        return mlab::concatenate({"[", argument::signature_string(*default_value ? "(Y)" : "(N)"), "]"});
                    }
                }
                return mlab::concatenate({"[", argument::signature_string(parser<T>::to_string(*default_value)), "]"});
            } else {
                return argument::signature_string(parser<T>::type_description());
            }
        }

        template <parsable T>
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
            static_assert(
                    std::is_same_v<T, int> or std::is_same_v<T, long> or
                            std::is_same_v<T, unsigned int> or std::is_same_v<T, unsigned long> or
                            std::is_same_v<T, long long> or std::is_same_v<T, unsigned long long> or
                            std::is_same_v<T, float> or std::is_same_v<T, double> or
                            std::is_same_v<T, bool>,
                    "You must implement a specialization of parser<T>::parse for this type.");

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

        namespace util {
            template <class T>
            concept is_std_to_stringable = requires(T const &value) {
                                               { std::to_string(value) } -> std::convertible_to<std::string>;
                                           };
        }

        template <class T>
        std::string parser<T>::to_string(T const &value) {
            static_assert(util::is_std_to_stringable<T> or std::is_same_v<T, std::string> or std::is_same_v<T, std::string_view>,
                          "You must implement a specialization of parser<T>::to_string for this type.");
            if constexpr (std::is_same_v<T, bool>) {
                // Override 0/1
                return value ? "true" : "false";
            } else if constexpr (util::is_std_to_stringable<T>) {
                return std::to_string(value);
            } else {
                return value;
            }
        }

        template <class T>
        std::string parser<T>::type_description() {
            return mlab::type_name<T>();
        }

        template <class T>
        std::string parser<std::optional<T>>::to_string(std::optional<T> const &value) {
            if (value) {
                static_assert(parse_can_output<T>);
                return parser<T>::to_string(*value);
            }
            return "<no value>";
        }

        r<std::string> parser<std::string>::parse(std::string_view value) {
            return std::string{value};
        }

        std::string parser<std::string>::to_string(std::string const &value) {
            return value;
        }

        std::string parser<std::string>::type_description() {
            return "string";
        }

        r<std::string_view> parser<std::string_view>::parse(std::string_view value) {
            return value;
        }

        std::string parser<std::string_view>::to_string(std::string_view const &value) {
            return std::string{value};
        }

        std::string parser<std::string_view>::type_description() {
            return "string";
        }

        template <parse_can_output R, class T, parsable... Args>
        command<R, T, Args...>::command(std::string_view name, T *obj_, R (T::*fn_)(Args...), typed_arguments_tuple_t<Args...> arg_seq)
            : command_base{name},
              typed_arguments_tuple_t<Args...>{std::move(arg_seq)},
              target_method<R, T, Args...>{obj_, fn_} {}

        template <parse_can_output R, class T, parsable... Args>
        command<R, T, Args...>::command(std::string_view name, T *obj_, R (T::*fn_)(Args...) const, typed_arguments_tuple_t<Args...> arg_seq)
            : command_base{name},
              typed_arguments_tuple_t<Args...>{std::move(arg_seq)},
              target_method<R, T, Args...>{obj_, fn_} {
            static_assert(std::is_const_v<T>, "You must explicitly mark the class type as const to call its const methods.");
        }

        template <parse_can_output R, class T, parsable... Args>
        command<R, T, Args...>::command(std::string_view name, R (*fn_)(Args...), typed_arguments_tuple_t<Args...> arg_seq)
            : command_base{name},
              typed_arguments_tuple_t<Args...>{std::move(arg_seq)},
              target_method<R, T, Args...>{fn_} {}


        template <parse_can_output R, class T, parsable... Args>
        r<Args...> command<R, T, Args...>::parse(std::vector<std::string_view> const &values) const {
            return parse(std::index_sequence_for<Args...>{}, values);
        }

        template <parse_can_output R, class T, parsable... Args>
        template <std::size_t... Is>
        [[nodiscard]] r<Args...> command<R, T, Args...>::parse(std::index_sequence<Is...>, std::vector<std::string_view> const &values) const {
            static_assert(sizeof...(Is) == sizeof...(Args));
            if constexpr (sizeof...(Is) == 0) {
                return mlab::result_success;
            } else {
                if (auto r_map = argument::map_values(values, {std::get<Is>(*this)...}); r_map) {
                    return mlab::concat_result(std::get<Is>(*this).parse((*r_map)[Is].second)...);
                } else {
                    return r_map.error();
                }
            }
        }

        template <parse_can_output R, class T, parsable... Args>
        template <std::size_t... Is>
        R command<R, T, Args...>::invoke(std::index_sequence<Is...>, r<Args...> args) {
            static_assert(sizeof...(Is) == sizeof...(Args));
            return (*this)(std::forward<Args>(mlab::get<Is>(args))...);
        }

        template <parse_can_output R, class T, parsable... Args>
        r<std::string> command<R, T, Args...>::parse_and_invoke(std::vector<std::string_view> const &values) {
            if (auto r_args = parse(std::index_sequence_for<Args...>{}, values); r_args) {
                if constexpr (std::is_void_v<R>) {
                    invoke(std::index_sequence_for<Args...>{}, std::move(r_args));
                    return {""};
                } else {
                    return parser<R>::to_string(invoke(std::index_sequence_for<Args...>{}, std::move(r_args)));
                }
            } else {
                return r_args.error();
            }
        }

        namespace util {
            template <std::size_t... Is>
            [[nodiscard]] std::string signature_impl(std::index_sequence<Is...>, auto const &targs) {
                return mlab::concatenate({std::get<Is>(targs).signature_string()...}, " ");
            }
            template <std::size_t... Is>
            [[nodiscard]] std::string help_impl(std::index_sequence<Is...>, std::string_view cmd_name, auto const &targs) {
                return mlab::concatenate({cmd_name, std::get<Is>(targs).help_string()...}, "\n    ");
            }
        }// namespace util

        template <parse_can_output R, class T, parsable... Args>
        std::string command<R, T, Args...>::signature() const {
            return util::signature_impl(std::index_sequence_for<Args...>{}, *this);
        }

        template <parse_can_output R, class T, parsable... Args>
        std::string command<R, T, Args...>::help() const {
            return util::help_impl(std::index_sequence_for<Args...>{}, name, *this);
        }

        template <class R, parsable... Args>
        void shell::register_command(std::string_view name, R (*fn)(Args...), typed_arguments_tuple_t<Args...> arg_seq) {
            _cmds.push_back(std::make_unique<command<R, void_struct, Args...>>(name, fn, std::move(arg_seq)));
        }

        template <class R, class T, parsable... Args>
        void shell::register_command(std::string_view name, T &obj, R (T::*fn)(Args...), typed_arguments_tuple_t<Args...> arg_seq) {
            _cmds.push_back(std::make_unique<command<R, T, Args...>>(name, &obj, fn, std::move(arg_seq)));
        }

        template <class R, class T, parsable... Args>
        void shell::register_command(std::string_view name, T const &obj, R (T::*fn)(Args...) const, typed_arguments_tuple_t<Args...> arg_seq) {
            _cmds.push_back(std::make_unique<command<R, const T, Args...>>(name, &obj, fn, std::move(arg_seq)));
        }
    }// namespace cmd

    namespace cmd_literals {

        auto operator""_pos(const char *name, std::size_t) {
            return ka::cmd::positional{name};
        }

        auto operator""_flag(const char *name, std::size_t) {
            return ka::cmd::flag{name};
        }

        auto operator""_arg(const char *name, std::size_t) {
            return ka::cmd::regular<void>{name};
        }
    }// namespace cmd_literals
}// namespace ka

#endif//KEYCARD_ACCESS_CONSOLE_HPP
