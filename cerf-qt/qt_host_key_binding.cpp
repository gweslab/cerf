#include "host_key_binding.h"

#include "qt_key_input.h"

#include <cerfcore/core/cerf_emulator.h>

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
};

}

REGISTER_SERVICE_AS(QtHostKeyBinding, cerffrontend::HostKeyBinding);
