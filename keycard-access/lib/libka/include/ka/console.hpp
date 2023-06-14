//
// Created by spak on 6/14/23.
//

#ifndef KEYCARD_ACCESS_CONSOLE_HPP
#define KEYCARD_ACCESS_CONSOLE_HPP

#include <string>
#include <string_view>

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
}

#endif//KEYCARD_ACCESS_CONSOLE_HPP
