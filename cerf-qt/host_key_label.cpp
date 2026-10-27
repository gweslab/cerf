#include "host_key_label.h"

#include "host_key_name.h"

namespace cerffrontend {

std::string HostKeyComboLabel(const std::vector<uint8_t>& vks) {
    std::string label;
    for (size_t i = 0; i < vks.size(); i++) {
        if (i) label += kHostKeyJoiner;
        label += HostKeyName(vks[i]);
    }
    return label;
}

}
