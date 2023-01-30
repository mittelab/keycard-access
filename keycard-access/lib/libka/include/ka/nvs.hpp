//
// Created by spak on 1/8/23.
//

#ifndef KEYCARD_ACCESS_NVS_HPP
#define KEYCARD_ACCESS_NVS_HPP

#include <esp_partition.h>
#include <map>
#include <memory>
#include <mlab/bin_data.hpp>
#include <mlab/result.hpp>
#include <nvs_flash.h>

namespace ka::nvs {

    class partition;
    class namespc;
    class const_namespc;

    enum struct error {
        not_found = ESP_ERR_NVS_NOT_FOUND,
        invalid_name = ESP_ERR_NVS_INVALID_NAME,
        invalid_length = ESP_ERR_NVS_INVALID_LENGTH,
        not_enough_space = ESP_ERR_NVS_NOT_ENOUGH_SPACE,
        read_only = ESP_ERR_NVS_READ_ONLY,
        too_long = ESP_ERR_NVS_VALUE_TOO_LONG,
        remove_failed = ESP_ERR_NVS_REMOVE_FAILED,
        fail = ESP_FAIL,
        invalid_handle = ESP_ERR_NVS_INVALID_HANDLE,
        other
    };

    template <class... Tn>
    using r = mlab::result<error, Tn...>;

    [[nodiscard]] error from_esp_error(esp_err_t esp_err);

    class nvs {
        std::map<std::string, std::weak_ptr<partition>> _open_partitions;

    public:
        nvs();
        nvs(nvs const &) = delete;
        nvs(nvs &&) = delete;
        nvs &operator=(nvs const &) = delete;
        nvs &operator=(nvs &&) = delete;
        ~nvs();

        [[nodiscard]] std::shared_ptr<partition> open_partition(const char *label, bool secure);
    };

    class partition : public std::enable_shared_from_this<partition> {
        esp_partition_t const *_part;
        mutable std::map<std::string, std::weak_ptr<const_namespc>> _open_cns;
        std::map<std::string, std::weak_ptr<namespc>> _open_ns;

    public:
        explicit partition(esp_partition_t const &part, bool secure);
        ~partition();

        partition(partition const &) = delete;
        partition(partition &&) noexcept = default;
        partition &operator=(partition const &) = delete;
        partition &operator=(partition &&) noexcept = default;

        [[nodiscard]] nvs_stats_t get_stats() const;

        [[nodiscard]] std::shared_ptr<namespc> open_namespc(const char *nsname);
        [[nodiscard]] inline std::shared_ptr<const_namespc> open_namespc(const char *nsname) const;
        [[nodiscard]] std::shared_ptr<const_namespc> open_const_namespc(const char *nsname) const;
    };

    class const_namespc {
    protected:
        std::shared_ptr<const partition> _part = nullptr;
        nvs_handle_t _hdl{};

        template <class T>
        using nvs_getter_t = esp_err_t (*)(nvs_handle_t, const char *, T *);

        template <class T>
        using nvs_sized_getter_t = esp_err_t (*)(nvs_handle_t, const char *, T *, std::size_t *);

        template <class T, nvs_getter_t<T> GetFn>
        [[nodiscard]] r<T> get_known_type(const char *key) const;

        template <class T, class U, nvs_sized_getter_t<U> GetFn>
        [[nodiscard]] r<T> get_known_sized_type(const char *key) const;

        friend class partition;
        const_namespc(std::shared_ptr<const partition> part, nvs_handle_t hdl);

    public:
        const_namespc() = default;
        const_namespc(const_namespc const &) = delete;
        const_namespc &operator=(const_namespc const &) = delete;
        const_namespc(const_namespc &&) noexcept = default;
        const_namespc &operator=(const_namespc &&) noexcept = default;

        [[nodiscard]] r<std::uint8_t> get_u8(const char *key) const;
        [[nodiscard]] r<std::uint16_t> get_u16(const char *key) const;
        [[nodiscard]] r<std::uint32_t> get_u32(const char *key) const;
        [[nodiscard]] r<std::uint64_t> get_u64(const char *key) const;
        [[nodiscard]] r<std::int8_t> get_i8(const char *key) const;
        [[nodiscard]] r<std::int16_t> get_i16(const char *key) const;
        [[nodiscard]] r<std::int32_t> get_i32(const char *key) const;
        [[nodiscard]] r<std::int64_t> get_i64(const char *key) const;
        [[nodiscard]] r<std::string> get_str(const char *key) const;
        [[nodiscard]] r<mlab::bin_data> get_blob(const char *key) const;

        [[nodiscard]] std::size_t used_entries() const;

        template <class T>
        [[nodiscard]] r<T> get(const char *key) const;

        ~const_namespc();
    };

    class namespc : public const_namespc {
        template <class T>
        using nvs_setter_t = esp_err_t (*)(nvs_handle_t, const char *, T);

        template <class T>
        using nvs_sized_setter_t = esp_err_t (*)(nvs_handle_t, const char *, T *, std::size_t);

        template <class T, nvs_setter_t<T> SetFn>
        r<> set_known_type(const char *key, T const &value);

        template <class T, class U, nvs_sized_setter_t<U> SetFn>
        r<> set_known_sized_type(const char *key, T const &value);

        friend class partition;
        namespc(std::shared_ptr<partition> part, nvs_handle_t hdl);

    public:
        namespc() = default;
        namespc(namespc const &) = delete;
        namespc &operator=(namespc const &) = delete;
        namespc(namespc &&) noexcept = default;
        namespc &operator=(namespc &&) noexcept = default;

        r<> set_u8(const char *key, std::uint8_t value);
        r<> set_u16(const char *key, std::uint16_t value);
        r<> set_u32(const char *key, std::uint32_t value);
        r<> set_u64(const char *key, std::uint64_t value);
        r<> set_i8(const char *key, std::int8_t value);
        r<> set_i16(const char *key, std::int16_t value);
        r<> set_i32(const char *key, std::int32_t value);
        r<> set_i64(const char *key, std::int64_t value);
        r<> set_str(const char *key, std::string const &value);
        r<> set_blob(const char *key, mlab::bin_data const &value);

        template <class T>
        r<> set(const char *key, T const &value);

        r<> commit();
        r<> erase(const char *key);
        r<> clear();
    };
}// namespace ka::nvs

namespace ka::nvs {
    template <class T>
    r<T> const_namespc::get(const char *key) const {
        if constexpr (std::is_same_v<T, std::uint8_t>) {
            return get_u8(key);
        } else if constexpr (std::is_same_v<T, std::uint16_t>) {
            return get_u16(key);
        } else if constexpr (std::is_same_v<T, std::uint32_t>) {
            return get_u32(key);
        } else if constexpr (std::is_same_v<T, std::uint64_t>) {
            return get_u64(key);
        } else if constexpr (std::is_same_v<T, std::int8_t>) {
            return get_i8(key);
        } else if constexpr (std::is_same_v<T, std::int16_t>) {
            return get_i16(key);
        } else if constexpr (std::is_same_v<T, std::int32_t>) {
            return get_i32(key);
        } else if constexpr (std::is_same_v<T, std::int64_t>) {
            return get_i64(key);
        } else if constexpr (std::is_same_v<T, std::string>) {
            return get_str(key);
        } else {
            static_assert(std::is_same_v<T, mlab::bin_data>,
                          "You must use one of the supported types.");
            return get_blob(key);
        }
    }
    template <class T>
    r<> namespc::set(const char *key, T const &value) {
        if constexpr (std::is_same_v<T, std::uint8_t>) {
            return set_u8(key, value);
        } else if constexpr (std::is_same_v<T, std::uint16_t>) {
            return set_u16(key, value);
        } else if constexpr (std::is_same_v<T, std::uint32_t>) {
            return set_u32(key, value);
        } else if constexpr (std::is_same_v<T, std::uint64_t>) {
            return set_u64(key, value);
        } else if constexpr (std::is_same_v<T, std::int8_t>) {
            return set_i8(key, value);
        } else if constexpr (std::is_same_v<T, std::int16_t>) {
            return set_i16(key, value);
        } else if constexpr (std::is_same_v<T, std::int32_t>) {
            return set_i32(key, value);
        } else if constexpr (std::is_same_v<T, std::int64_t>) {
            return set_i64(key, value);
        } else if constexpr (std::is_same_v<T, std::string>) {
            return set_str(key, value);
        } else {
            static_assert(std::is_same_v<T, mlab::bin_data>,
                          "You must use one of the supported types.");
            return set_blob(key, value);
        }
    }

    std::shared_ptr<const_namespc> partition::open_namespc(const char *nsname) const {
        return open_const_namespc(nsname);
    }
}// namespace ka::nvs

#endif//KEYCARD_ACCESS_NVS_HPP
