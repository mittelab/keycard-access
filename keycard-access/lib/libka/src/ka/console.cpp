//
// Created by spak on 6/14/23.
//

#include <driver/uart.h>
#include <esp_console.h>
#include <esp_log.h>
#include <esp_vfs_dev.h>
#include <ka/console.hpp>
#include <linenoise/linenoise.h>

namespace ka {

    std::string console::read_line(std::string_view prompt) const {
        auto reply = linenoise(prompt.data());
        std::string retval{reply};
        linenoiseFree(reply);
        return retval;
    }

    console::console() {

        /* Drain stdout before reconfiguring it */
        std::fflush(stdout);
        fsync(fileno(stdout));

        /* Disable buffering on stdin */
        std::setvbuf(stdin, nullptr, _IONBF, 0);

        /* Minicom, screen, idf_monitor send CR when ENTER key is pressed */
        esp_vfs_dev_uart_port_set_rx_line_endings(CONFIG_ESP_CONSOLE_UART_NUM, ESP_LINE_ENDINGS_CR);
        /* Move the caret to the beginning of the next line on '\n' */
        esp_vfs_dev_uart_port_set_tx_line_endings(CONFIG_ESP_CONSOLE_UART_NUM, ESP_LINE_ENDINGS_CRLF);


        /* Configure UART. Note that REF_TICK is used so that the baud rate remains
         * correct while APB frequency is changing in light sleep mode.
         */
        const uart_config_t uart_config = {
            .baud_rate = CONFIG_ESP_CONSOLE_UART_BAUDRATE,
            .data_bits = UART_DATA_8_BITS,
            .parity = UART_PARITY_DISABLE,
            .stop_bits = UART_STOP_BITS_1,
            .flow_ctrl = UART_HW_FLOWCTRL_DISABLE,
            .rx_flow_ctrl_thresh = 0,
#if SOC_UART_SUPPORT_REF_TICK
            .source_clk = UART_SCLK_REF_TICK,
#elif SOC_UART_SUPPORT_XTAL_CLK
            .source_clk = UART_SCLK_XTAL,
#endif
        };

        /* Install UART driver for interrupt-driven reads and writes */
        ESP_ERROR_CHECK(uart_driver_install(CONFIG_ESP_CONSOLE_UART_NUM,
                                            256, 0, 0, nullptr, 0));
        ESP_ERROR_CHECK(uart_param_config(CONFIG_ESP_CONSOLE_UART_NUM, &uart_config));

        /* Tell VFS to use UART driver */
        esp_vfs_dev_uart_use_driver(CONFIG_ESP_CONSOLE_UART_NUM);

        /* Initialize the console */
        esp_console_config_t console_config = {
            .max_cmdline_length = 256,
            .max_cmdline_args = 8,
#if CONFIG_LOG_COLORS
            .hint_color = 36 /* cyan */,
            .hint_bold = 0
#endif
        };
        ESP_ERROR_CHECK(esp_console_init(&console_config));
    }

    console::~console() {
        ESP_ERROR_CHECK_WITHOUT_ABORT(esp_console_deinit());
        esp_vfs_dev_uart_use_nonblocking(CONFIG_ESP_CONSOLE_UART_NUM);
        ESP_ERROR_CHECK_WITHOUT_ABORT(uart_driver_delete(CONFIG_ESP_CONSOLE_UART_NUM));
    }

    namespace cmd {
        r<value_argument_map> argument::map_values(std::vector<std::string_view> const &values, std::vector<std::reference_wrapper<const argument>> const &arguments) {
            value_argument_map retval;
            retval.reserve(arguments.size());
            // Copy the argument
            for (auto argref : arguments) {
                retval.emplace_back(argref, std::nullopt);
            }

            std::vector<std::string_view> positional;
            positional.reserve(values.size());

            // Assign flags and regular arguments, and collect positionals
            for (auto it = std::begin(values); it != std::end(values); ++it) {
                // Is it invoking help?
                if (*it == "-h" or *it == "--help") {
                    return error::help_invoked;
                }
                // After "--", they are all positionals.
                if (*it == "--") {
                    std::copy(std::next(it), std::end(values), std::back_inserter(positional));
                    break;
                }
                [&]() {
                    // Is it a flag or a regular argument starting with "--"?
                    if (it->starts_with("--")) {
                        for (auto jt = std::begin(retval); jt != std::end(retval); ++jt) {
                            argument const &a = jt->first.get();
                            if (a.type == argument_type::positional) {
                                continue;
                            }
                            if (it->substr(2) == a.token_main) {
                                if (a.type == argument_type::regular) {
                                    if (++it == std::end(values)) {
                                        break;
                                    }
                                }
                                jt->second = *it;
                                return;
                            } else if (a.type == argument_type::regular) {
                                // It's not a match
                                continue;
                            }
                            assert(a.type == argument_type::flag);
                            if (it->starts_with("--no-") and it->substr(5) == a.token_main) {
                                // It's a negative match
                                jt->second = *it;
                                return;
                            }
                        }
                    } else if (it->starts_with("-")) {
                        // Is it a flag or a regular argument starting with "-"?
                        for (auto jt = std::begin(retval); jt != std::end(retval); ++jt) {
                            argument const &a = jt->first.get();
                            if (a.type == argument_type::positional or a.token_alternate.empty()) {
                                continue;
                            }
                            if (it->substr(1) == a.token_alternate) {
                                if (a.type == argument_type::regular) {
                                    if (++it == std::end(values)) {
                                        break;
                                    }
                                }
                                jt->second = *it;
                                return;
                            } else if (a.type == argument_type::regular) {
                                // It's not a match
                                continue;
                            }
                            assert(a.type == argument_type::flag);
                            if (it->starts_with("-n") and it->substr(2) == a.token_alternate) {
                                // It's a negative match
                                jt->second = *it;
                                return;
                            }
                        }
                    } else {
                        // Definitely a positional
                        positional.emplace_back(*it);
                        return;
                    }
                    // If it gets here, either was not recognized, or we reached the end of the arguments
                    if (it == std::end(values)) {
                        --it;// Loop will stop
                    } else {
                        // Unrecognized arguments
                        ESP_LOGE("KA", "Unprocessed or unrecognized argument %s.", it->data());
                    }
                }();
            }

            // Assign positionals
            auto it = std::begin(positional);
            for (auto jt = std::begin(retval); jt != std::end(retval) and it != std::end(positional); ++jt) {
                argument const &a = jt->first.get();
                if (a.type != argument_type::positional) {
                    continue;
                }
                jt->second = *it++;
            }

            return retval;
        }

        std::string argument::signature_string(std::string_view value_marker) const {
            if (type == argument_type::positional) {
                return concatenate_views({"<", token_main, ">"});
            }

            if (type == argument_type::flag) {
                return concatenate_views({"--[no-]", token_main});
            }

            return concatenate_views({"--", token_main, " <", value_marker.empty() ? "value" : value_marker, ">"});
        }

        std::string argument::help_string(std::string_view type_info, std::string_view default_value) const {
            if (type == argument_type::positional) {
                if (type_info.empty()) {
                    return concatenate_views({"<", token_main, ">"});
                } else {
                    return concatenate_views({"<", token_main, ": ", type_info, ">"});
                }
            }

            const std::string_view lwrap = default_value.empty() ? "" : "[ ";
            const std::string_view rwrap = default_value.empty() ? "" : " ]";

            if (type == argument_type::flag) {
                if (token_alternate.empty()) {
                    return concatenate_views({lwrap, "--[no-]", token_main, rwrap});
                } else {
                    return concatenate_views({lwrap, "--[no-]", token_main, "|-[n]", token_alternate, rwrap});
                }
            }

            // type is regular
            const std::string_view token_alternate_prefix = token_alternate.empty() ? "" : " | -";
            if (default_value.empty() and type_info.empty()) {
                return concatenate_views({lwrap, "--", token_main, token_alternate_prefix, token_alternate, " <value>", rwrap});
            } else if (default_value.empty()) {
                return concatenate_views({lwrap, "--", token_main, token_alternate_prefix, token_alternate, " <(", type_info, ")>", rwrap});
            } else if (type_info.empty()) {
                return concatenate_views({lwrap, "--", token_main, token_alternate_prefix, token_alternate, " <", default_value, ">", rwrap});
            } else {
                return concatenate_views({lwrap, "--", token_main, token_alternate_prefix, token_alternate, " <", default_value, " (", type_info, ")>", rwrap});
            }
        }


        void shell::linenoise_completion(const char *typed, linenoiseCompletions *lc) const {
            for (auto const &cmd : _cmds) {
                if (cmd->name.starts_with(typed)) {
                    linenoiseAddCompletion(lc, cmd->name.data());
                }
            }
        }

        char *shell::linenoise_hints(const char *typed, int *color, int *bold) const {
            const std::string typed_s = typed;
            for (auto const &cmd : _cmds) {
                if (typed_s.starts_with(cmd->name)) {
                    auto s = cmd->signature();
                    char *retval = new char[s.size()];
                    std::copy(std::begin(s), std::end(s), retval);
                    return retval;
                }
            }
            return nullptr;
        }

        void shell::linenoise_free_hints(void *data) {
            char *strdata = reinterpret_cast<char *>(data);
            delete[] strdata;
        }
    }// namespace cmd
}// namespace ka
