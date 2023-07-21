//
// Created by spak on 7/18/23.
//

#include <ka/rpc.hpp>

namespace ka::rpc {

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


    r<mlab::bin_data> bridge::command_response(mlab::bin_data const &payload) const {
        if (_if == nullptr) {
            return error::transport_error;
        } else {
            if (const auto r = _if->send(payload); not r) {
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
            error e{};
            if (auto r_rcv = _if->receive(); r_rcv) {
                if (auto r_rsp = local_invoke(*r_rcv); r_rsp) {
                    if (auto r_txf = _if->send(*r_rsp); r_txf) {
                        continue;
                    } else {
                        e = r_txf.error();
                    }
                } else {
                    e = r_rsp.error();
                }
            } else {
                e = r_rcv.error();
            }
            // Is the error recoverable?
            if (e == error::channel_error or e == error::transport_error) {
                return e;
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
        if (const auto r_cmd = command_response(payload); r_cmd) {
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
        if (auto it = _cmds.find(std::string{uuid}); it != std::end(_cmds)) {
            mlab::bin_data payload;
            payload << mlab::prealloc(uuid.size() + 5 + body.size())
                    << command_type::user_command
                    << mlab::length_encoded << uuid
                    << body;
            return command_response(payload);
        } else {
            return error::invalid_argument;
        }
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

    struct bar {
        int foo(std::string_view) { return 32; }
    };

    void baz() {
        rpc::templated_command<int, bar, std::string_view> cmd{&bar::foo};

        bridge b{};
        b.register_command(&bar::foo);
    }
}// namespace ka::rpc