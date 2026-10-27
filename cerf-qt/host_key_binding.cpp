#include "host_key_binding.h"

#include "frontend_config.h"
#include "host_key_label.h"

#include <cerfcore/core/cerf_emulator.h>

namespace cerffrontend {

std::vector<uint8_t> HostKeyBinding::OrDefault(std::vector<uint8_t> vks) {
    if (vks.empty()) return {kDefaultVk};
    return vks;
}

void HostKeyBinding::OnReady() {
    vks_   = OrDefault(emu_.Get<FrontendConfig>().HostKeyVks());
    label_ = HostKeyComboLabel(vks_);
}

std::string HostKeyBinding::LabelWith(const char* suffix) const { return label_ + kHostKeyJoiner + suffix; }

int HostKeyBinding::IndexOf(uint32_t vk) const {
    for (size_t i = 0; i < vks_.size(); i++)
        if (vks_[i] == vk) return static_cast<int>(i);
    return -1;
}

}
