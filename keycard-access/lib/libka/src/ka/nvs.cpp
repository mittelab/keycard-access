//
// Created by spak on 1/8/23.
//

#include <cstring>
#include <esp_err.h>
#include <esp_log.h>
#include <ka/nvs.hpp>
#include <nvs_flash.h>

namespace ka::nvs {

    nvs::nvs() {
        esp_err_t err = nvs_flash_init();
        if (err == ESP_ERR_NVS_NO_FREE_PAGES or err == ESP_ERR_NVS_NEW_VERSION_FOUND) {
            // NVS partition was truncated and needs to be erased
            // Retry nvs_flash_init
            ESP_ERROR_CHECK(nvs_flash_erase());
            err = nvs_flash_init();
        } else
            ESP_ERROR_CHECK(err);
    }

    nvs::~nvs() {
        ESP_ERROR_CHECK(nvs_flash_deinit());
    }


    nvs &instance() {
        static nvs _instance{};
        return _instance;
    }

    std::shared_ptr<partition> nvs::open_default_partition() {
#ifdef CONFIG_NVS_ENCRYPTION
        return open_partition(NVS_DEFAULT_PART_NAME, true);
#else
        return open_partition(NVS_DEFAULT_PART_NAME, false);
#endif
    }

    std::shared_ptr<partition> nvs::open_partition(std::string_view label, bool secure) {
        std::unique_lock<std::mutex> lock{_partitions_mutex};
        auto &part_wptr = _open_partitions[std::string(label)];
        if (part_wptr.expired()) {
            // Attempt at finding the partition
            esp_partition_t const *part = esp_partition_find_first(
                    ESP_PARTITION_TYPE_ANY, ESP_PARTITION_SUBTYPE_ANY, label.data());
            if (part != nullptr) {
                auto part_sptr = std::shared_ptr<partition>{new partition{*part, secure}};
                part_wptr = part_sptr;
                return part_sptr;
            } else {
                ESP_LOGW("NVS", "Partition %s not found.", label.data());
            }
            return nullptr;
        } else {
            return part_wptr.lock();
        }
    }

    partition::partition(esp_partition_t const &part, bool secure) : _part{&part} {
        if (secure) {
#ifndef CONFIG_NVS_ENCRYPTION
            ESP_LOGE("NVS", "CONFIG_NVS_ENCRYPTION is not enable, cannot use secure features.");
#else
            std::abort();
            nvs_sec_cfg_t cfg{};
            esp_err_t err = nvs_flash_read_security_cfg(_part, &cfg);
            if (err == ESP_ERR_NVS_KEYS_NOT_INITIALIZED) {
                ESP_LOGI("NVS", "Uninitialized partition %s, generating keys.", _part->label);
                ESP_ERROR_CHECK(nvs_flash_generate_keys(_part, &cfg));
            }
            ESP_ERROR_CHECK(nvs_flash_secure_init_partition(_part->label, &cfg));
#endif
        } else {
            ESP_ERROR_CHECK(nvs_flash_init_partition(part.label));
        }
    }

    partition::~partition() {
        // Only deinit the non-nvs partitions, the NVS will be deinited by @ref nvs
        if (std::string(NVS_DEFAULT_PART_NAME) != std::string(_part->label)) {
            ESP_ERROR_CHECK(nvs_flash_deinit_partition(_part->label));
        }
    }

    const char *to_string(error e) {
        switch (e) {
            case error::not_found:
                return "not found";
            case error::invalid_name:
                return "invalid name";
            case error::invalid_length:
                return "invalid length";
            case error::not_enough_space:
                return "not enough space";
            case error::read_only:
                return "read only";
            case error::too_long:
                return "too long";
            case error::remove_failed:
                return "remove failed";
            case error::fail:
                return "fail";
            case error::invalid_handle:
                return "invalid handle";
            case error::parsing:
                return "parsing";
            default:
                return "UNKNOWN";
        }
    }

    error from_esp_error(esp_err_t esp_err) {
        switch (esp_err) {
            case ESP_ERR_NVS_NOT_FOUND:
                return error::not_found;
            case ESP_ERR_NVS_INVALID_NAME:
                return error::invalid_name;
            case ESP_ERR_NVS_INVALID_LENGTH:
                return error::invalid_length;
            case ESP_FAIL:
                return error::fail;
            case ESP_ERR_NVS_INVALID_HANDLE:
                return error::invalid_handle;
            case ESP_ERR_NVS_NOT_ENOUGH_SPACE:
                return error::not_enough_space;
            case ESP_ERR_NVS_READ_ONLY:
                return error::read_only;
            case ESP_ERR_NVS_VALUE_TOO_LONG:
                return error::too_long;
            case ESP_ERR_NVS_REMOVE_FAILED:
                return error::remove_failed;
            default:
                return error::other;
        }
    }

    template <class T, const_namespc::nvs_getter_t<T> GetFn>
    [[nodiscard]] r<T> const_namespc::get_known_type(std::string_view key) const {
        T value{};
        if (const auto e = GetFn(_hdl, key.data(), &value); e == ESP_OK) {
            return value;
        } else {
            return from_esp_error(e);
        }
    }

    template <class T, class U, const_namespc::nvs_sized_getter_t<U> GetFn>
    [[nodiscard]] r<T> const_namespc::get_known_sized_type(std::string_view key) const {
        std::size_t length = 0;
        if (const auto e = GetFn(_hdl, key.data(), nullptr, &length); e != ESP_OK) {
            return from_esp_error(e);
        }
        T value{};
        value.resize(length);
        if (const auto e = GetFn(_hdl, key.data(), value.data(), &length); e != ESP_OK) {
            return from_esp_error(e);
        }
        return value;
    }

    template <class T, namespc::nvs_setter_t<T> SetFn>
    r<> namespc::set_known_type(std::string_view key, T const &value) {
        if (const auto e = SetFn(_hdl, key.data(), value); e != ESP_OK) {
            return from_esp_error(e);
        }
        return mlab::result_success;
    }

    template <class T, class U, namespc::nvs_sized_setter_t<U> SetFn>
    r<> namespc::set_known_sized_type(std::string_view key, T const &value) {
        if (const auto e = SetFn(_hdl, key.data(), value.data(), value.size()); e != ESP_OK) {
            return from_esp_error(e);
        }
        return mlab::result_success;
    }

    const_namespc::const_namespc(std::shared_ptr<const partition> part, nvs_handle_t hdl)
        : _part{std::move(part)}, _hdl{hdl} {}


    std::shared_ptr<const partition> const_namespc::get_partition() const {
        return _part;
    }

    std::shared_ptr<partition> namespc::get_partition() {
        return std::const_pointer_cast<partition>(const_namespc::get_partition());
    }

    r<std::uint8_t> const_namespc::get_u8(std::string_view key) const {
        return get_known_type<std::uint8_t, nvs_get_u8>(key);
    }
    r<std::uint16_t> const_namespc::get_u16(std::string_view key) const {
        return get_known_type<std::uint16_t, nvs_get_u16>(key);
    }
    r<std::uint32_t> const_namespc::get_u32(std::string_view key) const {
        return get_known_type<std::uint32_t, nvs_get_u32>(key);
    }
    r<std::uint64_t> const_namespc::get_u64(std::string_view key) const {
        return get_known_type<std::uint64_t, nvs_get_u64>(key);
    }

    r<std::int8_t> const_namespc::get_i8(std::string_view key) const {
        return get_known_type<std::int8_t, nvs_get_i8>(key);
    }
    r<std::int16_t> const_namespc::get_i16(std::string_view key) const {
        return get_known_type<std::int16_t, nvs_get_i16>(key);
    }
    r<std::int32_t> const_namespc::get_i32(std::string_view key) const {
        return get_known_type<std::int32_t, nvs_get_i32>(key);
    }
    r<std::int64_t> const_namespc::get_i64(std::string_view key) const {
        return get_known_type<std::int64_t, nvs_get_i64>(key);
    }

    r<std::string> const_namespc::get_str(std::string_view key) const {
        return get_known_sized_type<std::string, char, nvs_get_str>(key);
    }

    std::size_t const_namespc::used_entries() const {
        std::size_t used_entries = 0;
        ESP_ERROR_CHECK(nvs_get_used_entry_count(_hdl, &used_entries));
        // 1 entry used by the namespace itself
        return used_entries + 1;
    }

    r<mlab::bin_data> const_namespc::get_blob(std::string_view key) const {
        return get_known_sized_type<mlab::bin_data, void, nvs_get_blob>(key);
    }
    r<> namespc::set_u8(std::string_view key, std::uint8_t value) {
        return set_known_type<std::uint8_t, nvs_set_u8>(key, value);
    }
    r<> namespc::set_u16(std::string_view key, std::uint16_t value) {
        return set_known_type<std::uint16_t, nvs_set_u16>(key, value);
    }
    r<> namespc::set_u32(std::string_view key, std::uint32_t value) {
        return set_known_type<std::uint32_t, nvs_set_u32>(key, value);
    }
    r<> namespc::set_u64(std::string_view key, std::uint64_t value) {
        return set_known_type<std::uint64_t, nvs_set_u64>(key, value);
    }
    r<> namespc::set_i8(std::string_view key, std::int8_t value) {
        return set_known_type<std::int8_t, nvs_set_i8>(key, value);
    }
    r<> namespc::set_i16(std::string_view key, std::int16_t value) {
        return set_known_type<std::int16_t, nvs_set_i16>(key, value);
    }
    r<> namespc::set_i32(std::string_view key, std::int32_t value) {
        return set_known_type<std::int32_t, nvs_set_i32>(key, value);
    }
    r<> namespc::set_i64(std::string_view key, std::int64_t value) {
        return set_known_type<std::int64_t, nvs_set_i64>(key, value);
    }
    r<> namespc::set_str(std::string_view key, std::string_view value) {
        return set_known_type<const char *, nvs_set_str>(key, value.data());
    }
    r<> namespc::set_blob(std::string_view key, mlab::bin_data const &value) {
        return set_known_sized_type<mlab::bin_data, const void, nvs_set_blob>(key, value);
    }

    r<> namespc::commit() {
        if (const auto e = nvs_commit(_hdl); e != ESP_OK) {
            return from_esp_error(e);
        }
        return mlab::result_success;
    }

    r<> namespc::erase(std::string_view key) {
        if (const auto e = nvs_erase_key(_hdl, key.data()); e != ESP_OK) {
            return from_esp_error(e);
        }
        return mlab::result_success;
    }

    r<> namespc::clear() {
        if (const auto e = nvs_erase_all(_hdl); e != ESP_OK) {
            return from_esp_error(e);
        }
        return mlab::result_success;
    }

    const_namespc::~const_namespc() {
        if (_part != nullptr) {
            nvs_close(_hdl);
        }
    }

    namespc::namespc(std::shared_ptr<partition> part, nvs_handle_t hdl)
        : const_namespc{std::move(part), hdl} {}


    nvs_stats_t partition::get_stats() const {
        nvs_stats_t s{};
        ESP_ERROR_CHECK(nvs_get_stats(_part->label, &s));
        return s;
    }

    std::shared_ptr<namespc> partition::open_namespc(std::string_view nsname) {
        std::unique_lock<std::mutex> lock{_ns_mutex};
        auto &ns_wptr = _open_ns[std::string(nsname)];
        if (ns_wptr.expired()) {
            // Attempt at finding the namespace
            nvs_handle_t hdl{};
            if (const auto e = nvs_open_from_partition(_part->label, nsname.data(), NVS_READWRITE, &hdl); e == ESP_OK) {
                auto ns_sptr = std::shared_ptr<namespc>{new namespc{shared_from_this(), hdl}};
                ns_wptr = ns_sptr;
                return ns_sptr;
            } else {
                ESP_LOGW("NVS", "Namespace %s not found: %s", nsname.data(), esp_err_to_name(e));
            }
            return nullptr;
        } else {
            return ns_wptr.lock();
        }
    }


    std::shared_ptr<const_namespc> partition::open_const_namespc(std::string_view nsname) const {
        std::unique_lock<std::mutex> lock{_cns_mutex};
        auto &ns_wptr = _open_cns[std::string(nsname)];
        if (ns_wptr.expired()) {
            // Do we have it in read-write?
            if (auto it = _open_ns.find(std::string(nsname)); it != std::end(_open_ns)) {
                if (not it->second.expired()) {
                    return it->second.lock();
                }
            }
            // Attempt at finding the namespace
            nvs_handle_t hdl{};
            if (const auto e = nvs_open_from_partition(_part->label, nsname.data(), NVS_READONLY, &hdl); e == ESP_OK) {
                auto ns_sptr = std::shared_ptr<const_namespc>{new const_namespc{shared_from_this(), hdl}};
                ns_wptr = ns_sptr;
                return ns_sptr;
            } else {
                ESP_LOGW("NVS", "Namespace %s not found: %s", nsname.data(), esp_err_to_name(e));
            }
            return nullptr;
        } else {
            return ns_wptr.lock();
        }
    }
}// namespace ka::nvs