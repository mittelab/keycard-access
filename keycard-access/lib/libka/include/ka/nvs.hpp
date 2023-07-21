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
#include <mutex>
#include <nvs_flash.h>

namespace ut {
    void test_nvs();
}

namespace ka::nvs {

    class nvs;

    [[nodiscard]] nvs &instance();

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
        other,
        parsing
    };

    [[nodiscard]] const char *to_string(error e);

    template <class... Tn>
    using r = mlab::result<error, Tn...>;

    [[nodiscard]] error from_esp_error(esp_err_t esp_err);

    /**
     * @note Opening a partition is thread-safe.
     */
    class nvs {
        std::map<std::string, std::weak_ptr<partition>> _open_partitions;
        std::mutex _partitions_mutex;

        nvs();

        friend nvs &instance();

    public:
        nvs(nvs const &) = delete;
        nvs(nvs &&) = delete;
        nvs &operator=(nvs const &) = delete;
        nvs &operator=(nvs &&) = delete;
        ~nvs();

        [[nodiscard]] std::shared_ptr<partition> open_partition(std::string_view label, bool secure);
        [[nodiscard]] std::shared_ptr<partition> open_default_partition();
    };

    /**
     * @note Opening a namespace is thread-safe.
     */
    class partition : public std::enable_shared_from_this<partition> {
        esp_partition_t const *_part;
        mutable std::map<std::string, std::weak_ptr<const_namespc>> _open_cns;
        std::map<std::string, std::weak_ptr<namespc>> _open_ns;
        std::mutex _ns_mutex;
        mutable std::mutex _cns_mutex;

        friend std::shared_ptr<partition> nvs::open_partition(std::string_view label, bool secure);

        explicit partition(esp_partition_t const &part, bool secure);

    public:
        ~partition();

        partition(partition const &) = delete;
        partition &operator=(partition const &) = delete;

        [[nodiscard]] nvs_stats_t get_stats() const;

        [[nodiscard]] std::shared_ptr<namespc> open_namespc(std::string_view nsname);
        [[nodiscard]] inline std::shared_ptr<const_namespc> open_namespc(std::string_view nsname) const;
        [[nodiscard]] std::shared_ptr<const_namespc> open_const_namespc(std::string_view nsname) const;
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
        [[nodiscard]] r<T> get_known_type(std::string_view key) const;

        template <class T, class U, nvs_sized_getter_t<U> GetFn>
        [[nodiscard]] r<T> get_known_sized_type(std::string_view key) const;

        friend class partition;
        const_namespc(std::shared_ptr<const partition> part, nvs_handle_t hdl);

    public:
        const_namespc() = default;
        const_namespc(const_namespc const &) = delete;
        const_namespc &operator=(const_namespc const &) = delete;
        const_namespc(const_namespc &&) noexcept = default;
        const_namespc &operator=(const_namespc &&) noexcept = default;

        [[nodiscard]] std::shared_ptr<const partition> get_partition() const;

        [[nodiscard]] r<std::uint8_t> get_u8(std::string_view key) const;
        [[nodiscard]] r<std::uint16_t> get_u16(std::string_view key) const;
        [[nodiscard]] r<std::uint32_t> get_u32(std::string_view key) const;
        [[nodiscard]] r<std::uint64_t> get_u64(std::string_view key) const;
        [[nodiscard]] r<std::int8_t> get_i8(std::string_view key) const;
        [[nodiscard]] r<std::int16_t> get_i16(std::string_view key) const;
        [[nodiscard]] r<std::int32_t> get_i32(std::string_view key) const;
        [[nodiscard]] r<std::int64_t> get_i64(std::string_view key) const;
        [[nodiscard]] r<std::string> get_str(std::string_view key) const;
        [[nodiscard]] r<mlab::bin_data> get_blob(std::string_view key) const;

        template <mlab::is_extractable T>
        [[nodiscard]] r<T> get_parse_blob(std::string_view key) const;

        [[nodiscard]] std::size_t used_entries() const;

        template <class T>
        [[nodiscard]] r<T> get(std::string_view key) const;

        ~const_namespc();
    };

    /**
     * @note This class is not necessarily thread-safe: it will call
     *  ESP's nvs_set_* functions without locking.
     */
    class namespc : public const_namespc {
        template <class T>
        using nvs_setter_t = esp_err_t (*)(nvs_handle_t, const char *, T);

        template <class T>
        using nvs_sized_setter_t = esp_err_t (*)(nvs_handle_t, const char *, T *, std::size_t);

        template <class T, nvs_setter_t<T> SetFn>
        r<> set_known_type(std::string_view key, T const &value);

        template <class T, class U, nvs_sized_setter_t<U> SetFn>
        r<> set_known_sized_type(std::string_view key, T const &value);

        friend class partition;
        namespc(std::shared_ptr<partition> part, nvs_handle_t hdl);

    public:
        namespc() = default;
        namespc(namespc const &) = delete;
        namespc &operator=(namespc const &) = delete;
        namespc(namespc &&) noexcept = default;
        namespc &operator=(namespc &&) noexcept = default;

        using const_namespc::get_partition;
        [[nodiscard]] std::shared_ptr<partition> get_partition();

        r<> set_u8(std::string_view key, std::uint8_t value);
        r<> set_u16(std::string_view key, std::uint16_t value);
        r<> set_u32(std::string_view key, std::uint32_t value);
        r<> set_u64(std::string_view key, std::uint64_t value);
        r<> set_i8(std::string_view key, std::int8_t value);
        r<> set_i16(std::string_view key, std::int16_t value);
        r<> set_i32(std::string_view key, std::int32_t value);
        r<> set_i64(std::string_view key, std::int64_t value);
        r<> set_str(std::string_view key, std::string_view value);
        r<> set_blob(std::string_view key, mlab::bin_data const &value);

        template <mlab::is_injectable T>
        r<> set_encode_blob(std::string_view key, T &&obj);

        template <class T>
        r<> set(std::string_view key, T &&value);

        r<> commit();
        r<> erase(std::string_view key);
        r<> clear();
    };
}// namespace ka::nvs

namespace ka::nvs {
    template <class T>
    r<T> const_namespc::get(std::string_view key) const {
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
        } else if constexpr (std::is_same_v<T, mlab::bin_data>) {
            return get_blob(key);
        } else {
            return get_parse_blob<T>(key);
        }
    }
    template <class T>
    r<> namespc::set(std::string_view key, T &&value) {
        if constexpr (std::is_same_v<std::decay_t<T>, std::uint8_t>) {
            return set_u8(key, value);
        } else if constexpr (std::is_same_v<std::decay_t<T>, std::uint16_t>) {
            return set_u16(key, value);
        } else if constexpr (std::is_same_v<std::decay_t<T>, std::uint32_t>) {
            return set_u32(key, value);
        } else if constexpr (std::is_same_v<std::decay_t<T>, std::uint64_t>) {
            return set_u64(key, value);
        } else if constexpr (std::is_same_v<std::decay_t<T>, std::int8_t>) {
            return set_i8(key, value);
        } else if constexpr (std::is_same_v<std::decay_t<T>, std::int16_t>) {
            return set_i16(key, value);
        } else if constexpr (std::is_same_v<std::decay_t<T>, std::int32_t>) {
            return set_i32(key, value);
        } else if constexpr (std::is_same_v<std::decay_t<T>, std::int64_t>) {
            return set_i64(key, value);
        } else if constexpr (std::is_same_v<std::decay_t<T>, std::string>) {
            return set_str(key, value);
        } else if constexpr (std::is_same_v<std::decay_t<T>, mlab::bin_data>) {
            return set_blob(key, value);
        } else {
            return set_encode_blob(key, value);
        }
    }

    std::shared_ptr<const_namespc> partition::open_namespc(std::string_view nsname) const {
        return open_const_namespc(nsname);
    }

    template <mlab::is_extractable T>
    [[nodiscard]] r<T> const_namespc::get_parse_blob(std::string_view key) const {
        if (const auto r = get_blob(key); r) {
            mlab::bin_stream s{*r};
            T t{};
            s >> t;
            if (s.bad() or not s.eof()) {
                return error::parsing;
            }
            return t;
        } else {
            return r.error();
        }
    }


    template <mlab::is_injectable T>
    r<> namespc::set_encode_blob(std::string_view key, T &&obj) {
        mlab::bin_data bd{};
        bd << obj;
        return set_blob(key, bd);
    }
}// namespace ka::nvs

#endif//KEYCARD_ACCESS_NVS_HPP
