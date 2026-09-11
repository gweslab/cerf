#include "../../peripherals/silicon_motion_sm501/siemens_mp377_sm501_internal.h"
#include "siemens_mp377_smi_bridge_c480.h"
#include "../../core/cerf_emulator.h"

namespace siemens_mp377 {

uint32_t SiemensMp377SmiBridgeC480::MmioBase() const {
    return kSmiBridgeBase;
}

uint32_t SiemensMp377SmiBridgeC480::MmioSize() const {
    return kSmiBridgeWindowBytes;
}

void SiemensMp377SmiBridgeC480::SaveState(StateWriter& w) {
    emu_.Get<SiemensMp377SmiBridge>().SaveState(w);
}

void SiemensMp377SmiBridgeC480::RestoreState(StateReader& r) {
    emu_.Get<SiemensMp377SmiBridge>().RestoreState(r);
}

void SiemensMp377SmiBridgeC480::PostRestore() {
    emu_.Get<SiemensMp377SmiBridge>().PostRestoreState();
}

REGISTER_SERVICE(SiemensMp377SmiBridgeC480);

} // namespace siemens_mp377
