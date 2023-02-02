//
// Created by spak on 1/8/23.
//

#include <ka/data.hpp>
#include <mlab/strutils.hpp>
#include <sodium/crypto_hash_sha512.h>

namespace ka {
    namespace util {

        std::string escape(std::string const &text) {
            return mlab::replace_all(mlab::replace_all(text, "\\", "\\\\"), "\n", "\\\n");
        }

        [[nodiscard]] token_id id_from_nfc_id(std::vector<std::uint8_t> const &d) {
            if (d.size() != token_id::array_size) {
                ESP_LOGE("KA", "NFC ID should be %d bytes long, not %d.", token_id::array_size, d.size());
            }
            token_id id{};
            std::copy_n(std::begin(d), std::min(token_id::array_size, d.size()), std::begin(id));
            return id;
        }
    }// namespace util

    std::string identity::string_representation() const {
        return mlab::data_to_hex_string(id) + "\n" + util::escape(holder) + "\n" + util::escape(publisher);
    }

    hash_type identity::hash() const {
        const std::string repr = string_representation();
        const mlab::bin_data data = mlab::bin_data::chain(
                mlab::prealloc(repr.size()),
                mlab::data_view_from_string(repr));
        hash_type h{};
        if (0 != crypto_hash_sha512(h.data(), data.data(), data.size())) {
            ESP_LOGE("KA", "Could not hash text and salt.");
            h = {};
        }
        return h;
    }

    bool identity::operator==(identity const &other) const {
        return id == other.id and holder == other.holder and publisher == other.publisher;
    }

    bool identity::operator!=(identity const &other) const {
        return id != other.id or holder != other.holder or publisher != other.publisher;
    }
}// namespace ka

namespace mlab {

    bin_stream &operator>>(bin_stream &s, ka::identity &id) {
        if (s.remaining() < 7 + 2 + 2) {
            s.set_bad();
            return s;
        }
        s >> id.id;
        std::uint16_t holder_length = 0, publisher_length = 0;
        s >> mlab::lsb16 >> holder_length;
        if (s.bad()) {
            return s;
        }
        if (s.remaining() < holder_length + 2) {
            s.set_bad();
            return s;
        }
        id.holder = data_to_string(s.read(holder_length));
        if (s.bad()) {
            return s;
        }
        s >> mlab::lsb16 >> publisher_length;
        if (s.remaining() < publisher_length) {
            s.set_bad();
            return s;
        }
        id.publisher = data_to_string(s.read(publisher_length));
        return s;
    }

    bin_data &operator<<(bin_data &bd, ka::identity const &id) {
        const auto holder_view = data_view_from_string(id.holder);
        const auto publisher_view = data_view_from_string(id.publisher);
        return bd << prealloc(bd.size() + id.id.size() + holder_view.size() + publisher_view.size() + 4)
                  << id.id
                  << mlab::lsb16 << holder_view.size()
                  << holder_view
                  << mlab::lsb16 << publisher_view.size()
                  << publisher_view;
    }
}// namespace mlab
