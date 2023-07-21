//
// Created by spak on 7/18/23.
//

#include <ka/rpc.hpp>
#include <mlab/result_macro.hpp>
#include <pn532/p2p.hpp>

using namespace std::chrono_literals;

namespace ka::rpc {


    const char *to_string(error e) {
        switch (e) {
            case error::parsing_error:
                return "parsing_error";
            case error::unknown_command:
                return "unknown_command";
            case error::mismatching_signature:
                return "mismatching_signature";
            case error::transport_error:
                return "transport_error";
            case error::channel_error:
                return "channel_error";
            case error::invalid_argument:
                return "invalid_argument";
            default:
                return "UNKNOWN";
        }
    }

    namespace {
        enum struct command_type : std::uint8_t {
            none = 0x00,
            query_signature,
            user_command = 0xff
        };
    }

    command_base::command_base(std::string signature_) : signature{std::move(signature_)} {}

    bridge::bridge(std::unique_ptr<bridge_interface_base> if_) : _if{std::move(if_)} {}

    r<std::string_view> bridge::register_command(std::string uuid, std::unique_ptr<command_base> cmd) {
        auto it = _cmds.lower_bound(uuid);
        if (it != std::end(_cmds) and it->first == uuid) {
            ESP_LOGE("RPC", "Duplicate command uuid %s", uuid.data());
            return error::invalid_argument;
        }
        return std::string_view{_cmds.insert(it, std::make_pair(std::move(uuid), std::move(cmd)))->first};
    }


    r<mlab::bin_data> bridge::command_response(mlab::bin_data payload) const {
        if (_if == nullptr) {
            return error::transport_error;
        } else {
            if (const auto r = _if->send(std::move(payload)); not r) {
                return r.error();
            }
            return _if->receive();
        }
    }

    r<> bridge::serve_loop() {
        _serve_stop = false;
        if (_if == nullptr) {
            return error::transport_error;
        }
        while (not _serve_stop) {
            TRY_RESULT_AS(_if->receive(), r_rcv) {
                TRY_RESULT_AS(local_invoke(*r_rcv), r_rsp) {
                    TRY(_if->send(std::move(*r_rsp)));
                }
            }
        }
        return mlab::result_success;
    }

    void bridge::serve_stop() {
        _serve_stop = true;
    }

    r<std::string> bridge::remote_get_signature(std::string_view uuid) const {
        mlab::bin_data payload;
        payload << mlab::prealloc(uuid.size() + 6)
                << command_type::query_signature
                << mlab::length_encoded << uuid;
        if (const auto r_cmd = command_response(std::move(payload)); r_cmd) {
            mlab::bin_stream s{*r_cmd};
            if (auto opt_sign = deserialize<std::string>(s); opt_sign) {
                return std::move(std::get<0>(*opt_sign));
            } else {
                return error::parsing_error;
            }
        } else {
            return r_cmd.error();
        }
    }

    r<mlab::bin_data> bridge::remote_invoke(std::string_view uuid, mlab::bin_data const &body) {
        mlab::bin_data payload;
        payload << mlab::prealloc(uuid.size() + 5 + body.size())
                << command_type::user_command
                << mlab::length_encoded << uuid
                << body;
        return command_response(std::move(payload));
    }

    r<mlab::bin_data> bridge::local_invoke(mlab::bin_data const &packed_cmd) const {
        mlab::bin_stream s{packed_cmd};
        auto cmd_type = command_type::none;
        std::string uuid{};
        s >> cmd_type >> mlab::length_encoded >> uuid;
        if (s.bad()) {
            return error::transport_error;
        }
        switch (cmd_type) {
            case command_type::none:
                return error::transport_error;
            case command_type::user_command:
                return local_invoke(uuid, s);
            case command_type::query_signature:
                if (auto sign = get_signature(uuid); sign.empty()) {
                    return error::unknown_command;
                } else {
                    return serialize<std::string_view>(sign);
                }
        }
        return error::transport_error;
    }

    r<mlab::bin_data> bridge::local_invoke(std::string_view uuid, mlab::bin_stream &s) const {
        if (auto it = _cmds.find(std::string{uuid}); it != std::end(_cmds)) {
            return it->second->command_response(s);
        } else {
            return error::unknown_command;
        }
    }

    bool bridge::contains(std::string_view uuid) const {
        return _cmds.find(std::string{uuid}) != std::end(_cmds);
    }

    r<std::string_view> bridge::lookup_uuid(std::string_view signature) const {
        auto retval_it = std::end(_cmds);
        for (auto it = std::begin(_cmds); it != std::end(_cmds); ++it) {
            if (it->second->signature == signature) {
                if (retval_it == std::end(_cmds)) {
                    retval_it = it;
                } else {
                    // Multiple signatures found
                    return error::invalid_argument;
                }
            }
        }
        if (retval_it == std::end(_cmds)) {
            return error::mismatching_signature;
        }
        return std::string_view{retval_it->first};
    }

    std::string_view bridge::get_signature(std::string_view uuid) const {
        if (auto it = _cmds.find(std::string{uuid}); it != std::end(_cmds)) {
            return it->second->signature;
        }
        return {};
    }
}// namespace ka::rpc

namespace ka::p2p {

    namespace {
        enum struct proto : std::uint8_t {
            send_command,
            req_command,
            ack_command,
            req_response,
            send_response,
            ack_response
        };
    }

    target_bridge_interface::target_bridge_interface(std::shared_ptr<pn532::p2p::target> tgt) : _tgt{std::move(tgt)} {}

    initiator_bridge_interface::initiator_bridge_interface(std::shared_ptr<pn532::p2p::initiator> ini) : _ini{std::move(ini)} {}

    ka::rpc::r<> target_bridge_interface::send_response(mlab::bin_data data) {
        if (_tgt == nullptr) {
            return ka::rpc::error::transport_error;
        }
        // Perform everything as a two-stroke engine triggered by the initiator
        if (const auto r_req_resp = _tgt->receive(5s); r_req_resp) {
            if (r_req_resp->size() != 1 or r_req_resp->back() != static_cast<std::uint8_t>(proto::req_response)) {
                ESP_LOGE("P2P", "Expected: %s, got:", "req_response");
                ESP_LOG_BUFFER_HEX_LEVEL("P2P", r_req_resp->data(), r_req_resp->size(), ESP_LOG_ERROR);
                return ka::rpc::error::transport_error;
            }
            // Good the initiator requested a response
        } else {
            MLAB_FAIL_MSG("_tgt->receive()", r_req_resp);
            return ka::rpc::error::channel_error;
        }
        // Actually send response, append the marker
        data << proto::send_response;
        if (const auto r_send_resp = _tgt->send(data, 5s); r_send_resp) {
            return mlab::result_success;
        } else {
            MLAB_FAIL_MSG("_tgt->send()", r_send_resp);
            return ka::rpc::error::channel_error;
        }
    }

    ka::rpc::r<> target_bridge_interface::send_command(mlab::bin_data data) {
        if (_tgt == nullptr) {
            return ka::rpc::error::transport_error;
        }
        // Perform everything as a two-stroke engine triggered by the initiator
        if (const auto r_req_cmd = _tgt->receive(5s); r_req_cmd) {
            if (r_req_cmd->size() != 1 or r_req_cmd->back() != static_cast<std::uint8_t>(proto::req_command)) {
                ESP_LOGE("P2P", "Expected: %s, got:", "req_command");
                ESP_LOG_BUFFER_HEX_LEVEL("P2P", r_req_cmd->data(), r_req_cmd->size(), ESP_LOG_ERROR);
                return ka::rpc::error::transport_error;
            }
            // Good the initiator requested a response
        } else {
            MLAB_FAIL_MSG("_tgt->receive()", r_req_cmd);
            return ka::rpc::error::channel_error;
        }
        // Actually send command, append the marker
        data << proto::send_command;
        if (const auto r_send_cmd = _tgt->send(data, 5s); r_send_cmd) {
            return mlab::result_success;
        } else {
            MLAB_FAIL_MSG("_tgt->send()", r_send_cmd);
            return ka::rpc::error::channel_error;
        }
    }

    ka::rpc::r<mlab::bin_data> target_bridge_interface::receive_command() {
        if (_tgt == nullptr) {
            return ka::rpc::error::transport_error;
        }
        // Perform everything as a two-stroke engine triggered by the initiator
        if (auto r_send_cmd = _tgt->receive(5s); r_send_cmd) {
            if (r_send_cmd->empty() or r_send_cmd->back() != static_cast<std::uint8_t>(proto::send_command)) {
                ESP_LOGE("P2P", "Expected: %s, got:", "send_command");
                ESP_LOG_BUFFER_HEX_LEVEL("P2P", r_send_cmd->data(), r_send_cmd->size(), ESP_LOG_ERROR);
                return ka::rpc::error::transport_error;
            }
            // Signal that it was acknowledged
            if (const auto r_send_ack = _tgt->send(mlab::bin_data::chain(proto::ack_command), 5s); not r_send_ack) {
                MLAB_FAIL_MSG("_tgt->send(ack_command)", r_send_ack);
                return ka::rpc::error::channel_error;
            }
            // Good the initiator sent a command
            r_send_cmd->pop_back();
            return std::move(*r_send_cmd);
        } else {
            MLAB_FAIL_MSG("_tgt->receive()", r_send_cmd);
            return ka::rpc::error::channel_error;
        }
    }

    ka::rpc::r<mlab::bin_data> target_bridge_interface::receive_response() {
        if (_tgt == nullptr) {
            return ka::rpc::error::transport_error;
        }
        // Perform everything as a two-stroke engine triggered by the initiator
        if (auto r_send_resp = _tgt->receive(5s); r_send_resp) {
            if (r_send_resp->empty() or r_send_resp->back() != static_cast<std::uint8_t>(proto::send_response)) {
                ESP_LOGE("P2P", "Expected: %s, got:", "send_command");
                ESP_LOG_BUFFER_HEX_LEVEL("P2P", r_send_resp->data(), r_send_resp->size(), ESP_LOG_ERROR);
                return ka::rpc::error::transport_error;
            }
            // Signal that it was acknowledged
            if (const auto r_send_ack = _tgt->send(mlab::bin_data::chain(proto::ack_response), 5s); not r_send_ack) {
                MLAB_FAIL_MSG("_tgt->send(ack_response)", r_send_ack);
                return ka::rpc::error::channel_error;
            }
            // Good the initiator sent a response
            r_send_resp->pop_back();
            return std::move(*r_send_resp);
        } else {
            MLAB_FAIL_MSG("_tgt->receive()", r_send_resp);
            return ka::rpc::error::channel_error;
        }
    }

    ka::rpc::r<> initiator_bridge_interface::send_command(mlab::bin_data data) {
        if (_ini == nullptr) {
            return ka::rpc::error::transport_error;
        }
        // Perform everything as a two-stroke engine triggered by the initiator
        data << proto::send_command;
        if (const auto r_send_cmd = _ini->communicate(data, 5s); r_send_cmd) {
            if (r_send_cmd->size() != 1 or r_send_cmd->back() != static_cast<std::uint8_t>(proto::ack_command)) {
                ESP_LOGE("P2P", "Expected: %s, got:", "ack_command");
                ESP_LOG_BUFFER_HEX_LEVEL("P2P", r_send_cmd->data(), r_send_cmd->size(), ESP_LOG_ERROR);
                return ka::rpc::error::transport_error;
            }
            // Good the target acknowledged the command
            return mlab::result_success;
        } else {
            MLAB_FAIL_MSG("_ini->communicate()", r_send_cmd);
            return ka::rpc::error::channel_error;
        }
    }

    ka::rpc::r<> initiator_bridge_interface::send_response(mlab::bin_data data) {
        if (_ini == nullptr) {
            return ka::rpc::error::transport_error;
        }
        // Perform everything as a two-stroke engine triggered by the initiator
        data << proto::send_response;
        if (const auto r_send_resp = _ini->communicate(data, 5s); r_send_resp) {
            if (r_send_resp->size() != 1 or r_send_resp->back() != static_cast<std::uint8_t>(proto::ack_response)) {
                ESP_LOGE("P2P", "Expected: %s, got:", "ack_response");
                ESP_LOG_BUFFER_HEX_LEVEL("P2P", r_send_resp->data(), r_send_resp->size(), ESP_LOG_ERROR);
                return ka::rpc::error::transport_error;
            }
            // Good the target acknowledged the response
            return mlab::result_success;
        } else {
            MLAB_FAIL_MSG("_ini->communicate()", r_send_resp);
            return ka::rpc::error::channel_error;
        }
    }

    ka::rpc::r<mlab::bin_data> initiator_bridge_interface::receive_command() {
        if (_ini == nullptr) {
            return ka::rpc::error::transport_error;
        }
        // Perform everything as a two-stroke engine triggered by the initiator
        if (auto r_req_cmd = _ini->communicate(mlab::bin_data::chain(proto::req_command), 5s); r_req_cmd) {
            if (r_req_cmd->empty() or r_req_cmd->back() != static_cast<std::uint8_t>(proto::send_command)) {
                ESP_LOGE("P2P", "Expected: %s, got:", "send_command");
                ESP_LOG_BUFFER_HEX_LEVEL("P2P", r_req_cmd->data(), r_req_cmd->size(), ESP_LOG_ERROR);
                return ka::rpc::error::transport_error;
            }
            // Good the target sent a command
            r_req_cmd->pop_back();
            return std::move(*r_req_cmd);
        } else {
            MLAB_FAIL_MSG("_ini->communicate()", r_req_cmd);
            return ka::rpc::error::channel_error;
        }
    }

    ka::rpc::r<mlab::bin_data> initiator_bridge_interface::receive_response() {
        if (_ini == nullptr) {
            return ka::rpc::error::transport_error;
        }
        // Perform everything as a two-stroke engine triggered by the initiator
        if (auto r_req_resp = _ini->communicate(mlab::bin_data::chain(proto::req_response), 5s); r_req_resp) {
            if (r_req_resp->empty() or r_req_resp->back() != static_cast<std::uint8_t>(proto::send_response)) {
                ESP_LOGE("P2P", "Expected: %s, got:", "send_response");
                ESP_LOG_BUFFER_HEX_LEVEL("P2P", r_req_resp->data(), r_req_resp->size(), ESP_LOG_ERROR);
                return ka::rpc::error::transport_error;
            }
            // Good the target sent a response
            r_req_resp->pop_back();
            return std::move(*r_req_resp);
        } else {
            MLAB_FAIL_MSG("_ini->communicate()", r_req_resp);
            return ka::rpc::error::channel_error;
        }
    }

    ka::rpc::r<mlab::bin_data> p2p_bridge_interface_base::receive() {
        switch (_last_action) {
            case bridge_last_action::response:
                _last_action = bridge_last_action::command;
                return receive_command();
            case bridge_last_action::command:
                _last_action = bridge_last_action::response;
                return receive_response();
        }
        return ka::rpc::error::transport_error;
    }

    ka::rpc::r<> p2p_bridge_interface_base::send(mlab::bin_data data) {
        switch (_last_action) {
            case bridge_last_action::response:
                _last_action = bridge_last_action::command;
                return send_command(std::move(data));
            case bridge_last_action::command:
                _last_action = bridge_last_action::response;
                return send_response(std::move(data));
        }
        return ka::rpc::error::transport_error;
    }
}// namespace ka::p2p