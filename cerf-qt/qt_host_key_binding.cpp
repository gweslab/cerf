#include <cerffrontend/host_key_binding.h>

#include "host_key_names.h"
#include "qt_host_key_names_platform.h"
#include "qt_key_input.h"

#include <cerfcore/core/cerf_emulator.h>

#include <cstdio>

namespace {

class QtHostKeyBinding : public cerffrontend::HostKeyBinding {
public:
    using cerffrontend::HostKeyBinding::HostKeyBinding;

    bool AllMembersDownNow() const override {
        const auto& keys = emu_.Get<QtKeyInput>();
        for (uint8_t vk : Vks())
            if (!keys.Down(vk)) return false;
        return true;
    }

protected:
    std::string KeyName(uint8_t vk) const override {
        for (const HostKeyName& n : PlatformHostKeyNames())
            if (n.vk == vk) return n.name;
        for (const HostKeyName& n : kHostKeyNames)
            if (n.vk == vk) return n.name;
        char fallback[16] = {};
        std::snprintf(fallback, sizeof(fallback), "VK 0x%02X", static_cast<unsigned>(vk));
        return fallback;
    }
};

}

REGISTER_SERVICE_AS(QtHostKeyBinding, cerffrontend::HostKeyBinding);
