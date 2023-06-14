//
// Created by spak on 6/14/23.
//

#ifndef KEYCARD_ACCESS_DEVICE_HPP
#define KEYCARD_ACCESS_DEVICE_HPP

#include <ka/key_pair.hpp>
#include <ka/nvs.hpp>
#include <ka/ota.hpp>
#include <ka/wifi.hpp>

namespace ka {
    class device {
        key_pair _kp;
        std::shared_ptr<wifi> _wf;
        ota_watch _ota;

    protected:
        [[nodiscard]] virtual nvs::r<> save_settings(nvs::partition &partition) const;
        [[nodiscard]] virtual nvs::r<> load_settings(nvs::partition const &partition);
        [[nodiscard]] virtual nvs::r<> clear_settings(nvs::partition &partition) const;

    public:
        device();
    };
}// namespace ka

#endif//KEYCARD_ACCESS_DEVICE_HPP
