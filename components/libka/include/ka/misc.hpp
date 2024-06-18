//
// Created by spak on 6/28/23.
//

#ifndef KEYCARD_ACCESS_MISC_HPP
#define KEYCARD_ACCESS_MISC_HPP

#include <type_traits>
#include <utility>

namespace ka {

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
        using fn_ptr_t = std::conditional_t<std::is_const_v<T>, R (T::*)(Args...) const, R (T::*)(Args...)>;

        target_ptr_t target;
        fn_ptr_t method;

        target_method(target_ptr_t target_, fn_ptr_t method_) : target{target_}, method{method_} {}

        auto operator()(Args... args) {
            return ((*target).*method)(std::forward<Args>(args)...);
        }
    };

    template <class R, class... Args>
    struct target_method<R, void_struct, Args...> {
        using fn_ptr_t = R (*)(Args...);

        fn_ptr_t method;

        explicit target_method(fn_ptr_t method_) : method{method_} {}

        auto operator()(Args... args) {
            return method(std::forward<Args>(args)...);
        }
    };

}// namespace ka

#endif//KEYCARD_ACCESS_MISC_HPP
