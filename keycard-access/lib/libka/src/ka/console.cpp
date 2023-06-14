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
}// namespace ka
