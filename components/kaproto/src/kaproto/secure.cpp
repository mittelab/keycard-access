//
// Created by spak on 25/08/24.
//

#include <kaproto/secure.hpp>
#include <mutex>
#include <rom/uart.h>
#include <sodium/crypto_kx.h>
#include <sodium/crypto_secretstream_xchacha20poly1305.h>
#include <sodium/randombytes.h>
#include <mlab/result_macro.hpp>
#include <esp_random.h>
#include <chrono>

namespace ka::proto {
    using namespace std::chrono_literals;

    namespace {
        using jt = json::value_t;
    }

    bool validate_jsonrpc_request(json const &j) {
        return json_validate<jt::string>(j, "jsonrpc", false, "2.0")
               and json_validate<jt::string>(j, "method", false)
               and json_validate<jt::string, jt::number_integer, jt::number_unsigned, jt::null>(j, "id", true)
               and json_validate<jt::array, jt::object, jt::null>(j, "params", true);
    }

    bool validate_jsonrpc_error(json const &j) {
        return json_validate<jt::number_integer, jt::number_unsigned>(j, "code")
               and json_validate<jt::string>(j, "message")
               and json_validate(j, "data", true);
    }


    bool validate_jsonrpc_response(json const &j) {
        if (json_validate<jt::string>(j, "jsonrpc", false, "2.0")
            and json_validate<jt::number_integer, jt::number_unsigned, jt::string>(j, "id", false)) {
            // Either result or error
            if (json_validate(j, "result", false)) {
                return not json_validate(j, "error", false);
            }
            // If error, must be validatable
            return json_validate(j, "error", false, validate_jsonrpc_error);
        }
        return false;
    }


    uuid::uuid(randomize_t) : _data{} {
        esp_fill_random(_data.data(), _data.size());
        _data[6] = 0x40 | (_data[6] & 0xf);
        _data[8] = 0x80 | (_data[8] & 0b00111111);
    }

    [[nodiscard]] std::size_t uuid::hash() const {
        // Interprete this as string
        const std::string_view sv{reinterpret_cast<const char *>(_data.data()), _data.size()};
        const std::hash<std::string_view> h{};
        return h(sv);
    }


    std::string uuid::to_string() const {
        std::string buffer;
        buffer.resize(37);
        std::snprintf(buffer.data(), buffer.size(),
                      "%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x",
                      _data[0], _data[1], _data[2], _data[3], _data[4], _data[5], _data[6], _data[7],
                      _data[8], _data[9], _data[10], _data[11], _data[12], _data[13], _data[14], _data[15]
        );
        buffer.resize(36);
        return buffer;
    }

    std::optional<uuid> uuid::from_string(std::string_view s) {
        static constexpr auto fmt =
            "%02hhx%02hhx%02hhx%02hhx-%02hhx%02hhx-%02hhx%02hhx-%02hhx%02hhx-%02hhx%02hhx%02hhx%02hhx%02hhx%02hhx";
        if (s.length() != 36) {
            return std::nullopt;
        }
        uuid retval{};
        if (16 != std::sscanf(s.data(), fmt,
                              &retval._data[0], &retval._data[1], &retval._data[2], &retval._data[3], &retval._data[4],
                              &retval._data[5], &retval._data[6], &retval._data[7], &retval._data[8], &retval._data[9],
                              &retval._data[10], &retval._data[11], &retval._data[12], &retval._data[13],
                              &retval._data[14], &retval._data[15])) {
            return std::nullopt;
        }
        return retval;
    }

    r<std::future<json>> secure_channel::store_send_request(json req_body, ms timeout) {
        const mlab::reduce_timeout rt{timeout};
        const auto req_id = uuid{randomize};
        req_body["id"] = req_id.to_string();

        if (not jsonrpc_validate_request(req_body)) {
            return error::invalid_argument;
        }

        const auto request_cbor = json::to_cbor(req_body);
        const auto request_cbor_range = mlab::make_range(
            request_cbor.data(), request_cbor.data() + request_cbor.size());
        auto shared_fut = std::future<json>{};
        {
            const std::unique_lock lock{_pending_requests, rt.remaining()};
            if (not lock) {
                return error::timeout;
            }
            auto promise = std::promise<std::pair<json>{};
            shared_fut = promise.get_future();
            _pending_requests[req_id] = std::move(promise);
        }
        if (const auto r = send_packet(request_cbor_range, rt.remaining()); not r) {
            const std::unique_lock lock{_pending_requests /* do not allow timeout here */};
            _pending_requests.erase(req_id);
            return r.error();
        }
        return shared_fut;
    }


    r<json, bool> secure_channel::response_or_error(std::future<json> &fut, ms timeout) {
        switch (fut.wait_for(timeout)) {
            case std::future_status::deferred:
                return error::system_error;
            case std::future_status::timeout:
                return error::timeout;
            case std::future_status::ready:
                break;
        }
        json resp_body = fut.get();
        if (resp_body.contains("result")) {
            return {std::move(resp_body["result"]), true};
        }
        return {std::move(resp_body["error"]), false};
    }


    r<json> secure_channel::log_error(r<json, bool> res) {
        if (not res) {
            return res.error();
        }
        if (res->second) {
            return std::move(res->first);
        }
        auto const &err = res->first;
        const auto err_code = err["code"].get<int>();
        const auto err_msg = err["message"].get<std::string_view>();
        ESP_LOGW("KA", "Request failed with error %d: %s", err_code, err_msg.data());
        return error::application_error;
    }

    void secure_channel::handle_response(json resp_body) {
        if (not jsonrpc_validate_response(resp_body)) {
            const auto s = resp_body.dump();
            ESP_LOGE("KA", "Invalid response body: %s.", s.c_str());
            return;
        }

        // Attempt at parsing this UUID
        uuid req_id{};
        auto validate = [&](json const &json_id) -> bool {
            if (const auto r = uuid::from_string(json_id.get<std::string_view>()); r) {
                req_id = *r;
                return true;
            }
            return false;
        };

        if (not json_validate<json_value_type::string>(resp_body, "id", false, validate)) {
            ESP_LOGE("KA", "Response to a request not sent through this library.");
            return;
        }

        // Now req_id contains a valid UUID, attempt to store the result
        const std::unique_lock lock{_pending_requests, 1s};
        if (not lock) {
            const auto uuid_str = req_id.to_string();
            ESP_LOGE("KA", "Timeout when trying to store response result for request %s", uuid_str.c_str());
            return;
        }

        // Pop the promise from the list and set the result
        if (const auto it = _pending_requests.find(req_id); it == std::end(_pending_requests)) {
            const auto uuid_str = req_id.to_string();
            ESP_LOGE("KA", "Unable to find promise for response %s", uuid_str.c_str());
        } else {
            // Set the result and trash the promise
            auto promise = std::move(it->second);
            _pending_requests.erase(it);
            promise.set_value(std::move(resp_body));
        }
    }


    r<> secure_channel::send_raw_packet(mlab::range<std::uint8_t const *> packet, ms timeout) {
        if (packet.size() > max_packet_size) {
            return error::invalid_argument;
        }
        const mlab::reduce_timeout rt{timeout};
        const std::unique_lock lock{_send_mutex, rt.remaining()};
        if (not lock) {
            return error::timeout;
        }
        const auto packet_len = mlab::encode<mlab::byte_order::lsb_first, 32>(packet.size());
        const auto packet_len_rg = mlab::make_range(packet_len);
        if (const auto res = _socket.send(packet_len_rg, rt.remaining()); not res) {
            return res;
        }
        return _socket.send(packet, rt.remaining());
    }

    r<mlab::bin_data> secure_channel::recv_raw_packet(ms timeout) {
        const mlab::reduce_timeout rt{timeout};
        const std::unique_lock lock{_recv_mutex, rt.remaining()};
        if (not lock) {
            return error::timeout;
        }
        mlab::bin_data buffer{mlab::prealloc(4)};
        if (const auto res = _socket.recv(buffer.data_view(), rt.remaining()); not res) {
            return res.error();
        }
        // Extract the packet length
        std::uint32_t packet_length = 0;
        mlab::bin_stream s{buffer};
        s >> mlab::lsb32 >> packet_length;
        if (s.bad() or packet_length == 0 or packet_length > max_packet_size) {
            return error::malformed;
        }
        // Allocate the buffer
        buffer.resize(packet_length);
        if (const auto res = _socket.recv(buffer.data_view(), rt.remaining()); not res) {
            return res.error();
        }
        return buffer;
    }

    namespace {
        struct handshake_state {
            mlab::bin_data own_ephemeral_pk{};
            mlab::bin_data peer_ephemeral_pk{};

            std::array<std::uint8_t, crypto_kx_SECRETKEYBYTES> own_ephemeral_sk{};

            std::array<std::uint8_t, crypto_kx_SESSIONKEYBYTES> rx_key{};
            std::array<std::uint8_t, crypto_kx_SESSIONKEYBYTES> tx_key{};

            handshake_state() {
                own_ephemeral_pk.resize(crypto_kx_PUBLICKEYBYTES);
                crypto_kx_keypair(own_ephemeral_pk.data(), own_ephemeral_sk.data());
                // Safety measure in case we accidentally make use of these keys:
                randombytes_buf(tx_key.data(), tx_key.size());
                randombytes_buf(rx_key.data(), rx_key.size());
            }

            [[nodiscard]] r<> recv_peer_ephemeral_pk(r<mlab::bin_data> packet) {
                if (not packet) {
                    return packet.error();
                }
                if (packet->size() != crypto_kx_PUBLICKEYBYTES) {
                    ESP_LOGE("KA", "Received invalid length peer %s", "public key");
                    return error::malformed;
                }
                peer_ephemeral_pk = std::move(*packet);
                return mlab::result_success;
            }

            [[nodiscard]] r<> derive_session_keys(bool is_server) {
                if (peer_ephemeral_pk.size() != crypto_kx_PUBLICKEYBYTES
                    or own_ephemeral_pk.size() != crypto_kx_PUBLICKEYBYTES) {
                    return error::system_error;
                }

                // Choose derivation function based on the argument
                const auto &crypto_kx_session_keys = is_server
                                                         ? crypto_kx_server_session_keys
                                                         : crypto_kx_client_session_keys;

                if (0 != crypto_kx_session_keys(rx_key.data(), tx_key.data(), own_ephemeral_pk.data(),
                                                own_ephemeral_sk.data(), peer_ephemeral_pk.data())) {
                    ESP_LOGE("KA", "Unable to derive ephemeral session keys.");
                    return error::crypto_error;
                }
                return mlab::result_success;
            }

            [[nodiscard]] mlab::bin_data prepare_push_packet(
                crypto_secretstream_xchacha20poly1305_state &send_state) const {
                mlab::bin_data packet;
                packet.resize(crypto_secretstream_xchacha20poly1305_HEADERBYTES);
                crypto_secretstream_xchacha20poly1305_init_push(&send_state, packet.data(), tx_key.data());
                return packet;
            }

            [[nodiscard]] r<> recv_peer_pull_packet(crypto_secretstream_xchacha20poly1305_state &recv_state,
                                                    r<mlab::bin_data> packet) const {
                if (not packet) {
                    return packet.error();
                }
                if (packet->size() != crypto_secretstream_xchacha20poly1305_HEADERBYTES) {
                    ESP_LOGE("KA", "Received invalid length peer %s", "header packet");
                    return error::malformed;
                }
                crypto_secretstream_xchacha20poly1305_init_pull(&recv_state, packet->data(), rx_key.data());
                return mlab::result_success;
            }
        };
    }

    r<> secure_channel::handshake_as_client(ms timeout) {
        const mlab::reduce_timeout rt{timeout};

        // Generate own keypair
        handshake_state state{};

        // Send our own ephemeral PK
        TRY(send_raw_packet(state.own_ephemeral_pk.data_view(), rt.remaining()));
        // Retrieve the peer ephemeral PK
        TRY(state.recv_peer_ephemeral_pk(recv_raw_packet(rt.remaining())));

        // Derive the session keys
        TRY(state.derive_session_keys(false));

        // Prepare and send the initialization packet
        const auto push_packet = state.prepare_push_packet(_send_state);
        TRY(send_raw_packet(push_packet.data_view(), rt.remaining()));
        // Receive the peer's packet to initialize our own recv state
        TRY(state.recv_peer_pull_packet(_recv_state, recv_raw_packet(rt.remaining())));

        return mlab::result_success;
    }

    r<> secure_channel::handshake_as_server(ms timeout) {
        const mlab::reduce_timeout rt{timeout};

        // Generate own keypair
        handshake_state state{};

        // Retrieve the peer ephemeral PK
        TRY(state.recv_peer_ephemeral_pk(recv_raw_packet(rt.remaining())));
        // Send our own ephemeral PK
        TRY(send_raw_packet(state.own_ephemeral_pk.data_view(), rt.remaining()));

        // Derive the session keys
        TRY(state.derive_session_keys(true));

        // Receive the peer's packet to initialize our own recv state
        TRY(state.recv_peer_pull_packet(_recv_state, recv_raw_packet(rt.remaining())));
        // Prepare and send the initialization packet
        const auto push_packet = state.prepare_push_packet(_send_state);
        TRY(send_raw_packet(push_packet.data_view(), rt.remaining()));

        return mlab::result_success;
    }


    r<> secure_channel::send_packet(mlab::range<std::uint8_t const *> packet, ms timeout) {
        mlab::bin_data ciphertext;
        ciphertext.resize(packet.size() + crypto_secretstream_xchacha20poly1305_ABYTES);
        // Unfortuntately it doesn't seem to allow in-place encryption
        if (0 != crypto_secretstream_xchacha20poly1305_push(
                &_send_state, ciphertext.data(), nullptr,
                packet.data(), packet.size(), nullptr, 0, 0)) {
            return error::crypto_error;
        }
        return send_raw_packet(ciphertext.data_view(), timeout);
    }

    r<mlab::bin_data> secure_channel::recv_packet(ms timeout) {
        auto recv_res = recv_raw_packet(timeout);
        if (not recv_res) {
            return recv_res.error();
        }
        // This one instead can be used in-place
        if (0 != crypto_secretstream_xchacha20poly1305_pull(
                &_recv_state, recv_res->data(), nullptr, nullptr,
                recv_res->data(), recv_res->size(), nullptr, 0)) {
            return error::crypto_error;
        }
        // Truncate by crypto_secretstream_xchacha20poly1305_ABYTES
        recv_res->resize(recv_res->size() - crypto_secretstream_xchacha20poly1305_ABYTES);
        return recv_res;
    }
}
