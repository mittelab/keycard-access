//
// Created by spak on 1/16/23.
//

#include <ka/nfc_p2p.hpp>

namespace ka::nfc {

    result<mlab::bin_data> pn532_initiator::communicate(mlab::bin_data const &data, ms timeout) {
        if (_controller == nullptr) {
            return pn532::channel::error::failure;
        }
        if (auto r = controller().initiator_data_exchange(target_logical_index(), data, timeout); r) {
            return std::move(r->second);
        } else {
            return r.error();
        }
    }

    result<> pn532_initiator::goodbye() {
        if (_controller == nullptr) {
            return pn532::channel::error::failure;
        }
        return controller().initiator_release(target_logical_index());
    }

    [[nodiscard]] result<mlab::bin_data> pn532_target::receive(ms timeout) {
        if (_controller == nullptr) {
            return pn532::channel::error::failure;
        }
        if (auto r = controller().target_get_data(timeout); r) {
            return std::move(r->second);
        } else {
            return r.error();
        }
    }

    [[nodiscard]] result<> pn532_target::send(mlab::bin_data const &data, ms timeout) {
        if (_controller == nullptr) {
            return pn532::channel::error::failure;
        }
        if (const auto r = controller().target_set_data(data, timeout); not r) {
            return r.error();
        }
        return mlab::result_success;
    }

    pn532_initiator::pn532_initiator(std::shared_ptr<pn532::controller> controller, std::uint8_t log_idx)
        : _controller{std::move(controller)}, _idx{log_idx} {}

    pn532_target::pn532_target(std::shared_ptr<pn532::controller> controller)
        : _controller{std::move(controller)} {}

    result<pn532::init_as_target_res> pn532_target::init_as_target(ms timeout, std::array<std::uint8_t, 10> nfcid_3t) {
        if (_controller == nullptr) {
            return pn532::channel::error::failure;
        }
        const pn532::mifare_params mp{
                .sens_res = {0x04, 0x00},
                .nfcid_1t = {nfcid_3t[0], nfcid_3t[1], nfcid_3t[2]},
                .sel_res = pn532::bits::sel_res_dep_mask
        };
        const pn532::felica_params fp {
                .nfcid_2t = {nfcid_3t[3], nfcid_3t[4], nfcid_3t[5], nfcid_3t[6], nfcid_3t[7], nfcid_3t[8]},
                .pad = {0xc0, 0xc1, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7},
                .syst_code = {0xff, 0xff}
        };
        return controller().target_init_as_target(false, true, false, mp, fp, nfcid_3t, {}, {}, timeout);
    }

}