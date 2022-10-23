//
// Created by spak on 10/23/22.
//

#ifndef KEYCARDACCESS_HELPERS_HPP
#define KEYCARDACCESS_HELPERS_HPP

namespace ka {

    bool mbedtls_logcheck(int mbedtls_err_code, const char *fn_desc = nullptr);

    template <class T, void (*InitFn)(T *), void (*FreeFn)(T *)>
    class managed {
        T _obj;

    public:
        managed();
        managed(managed const &) = delete;
        managed(managed &&) = delete;

        managed &operator=(managed const &) = delete;
        managed &operator=(managed &&) = delete;

        [[nodiscard]] operator T *();

        [[nodiscard]] operator T const *() const;

        [[nodiscard]] T *operator->();

        [[nodiscard]] T const *operator->() const;


        [[nodiscard]] T &operator*();

        [[nodiscard]] T const &operator*() const;

        ~managed();
    };
}// namespace ka

namespace ka {
    template <class T, void (*InitFn)(T *), void (*FreeFn)(T *)>
    managed<T, InitFn, FreeFn>::managed() : _obj{} {
        InitFn(&_obj);
    }


    template <class T, void (*InitFn)(T *), void (*FreeFn)(T *)>
    managed<T, InitFn, FreeFn>::operator T *() {
        return &_obj;
    }

    template <class T, void (*InitFn)(T *), void (*FreeFn)(T *)>
    managed<T, InitFn, FreeFn>::operator T const *() const {
        return &_obj;
    }

    template <class T, void (*InitFn)(T *), void (*FreeFn)(T *)>
    T *managed<T, InitFn, FreeFn>::operator->() {
        return &_obj;
    }

    template <class T, void (*InitFn)(T *), void (*FreeFn)(T *)>
    T const *managed<T, InitFn, FreeFn>::operator->() const {
        return &_obj;
    }


    template <class T, void (*InitFn)(T *), void (*FreeFn)(T *)>
    T &managed<T, InitFn, FreeFn>::operator*() {
        return _obj;
    }

    template <class T, void (*InitFn)(T *), void (*FreeFn)(T *)>
    T const &managed<T, InitFn, FreeFn>::operator*() const {
        return _obj;
    }

    template <class T, void (*InitFn)(T *), void (*FreeFn)(T *)>
    managed<T, InitFn, FreeFn>::~managed() {
        FreeFn(&_obj);
    }
}// namespace ka

#endif//KEYCARDACCESS_HELPERS_HPP
