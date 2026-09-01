#include "cerf_virt_customizations_reset.h"

#include "../../core/cerf_emulator.h"
#include "../../core/device_config.h"
#include "../../core/log.h"
#include "../../host/boot_screen.h"
#include "../../socs/guest_cpu_reset.h"

REGISTER_SERVICE(CerfVirtCustomizationsReset);

bool CerfVirtCustomizationsReset::ShouldRegister() {
    return emu_.Get<DeviceConfig>().guest_additions;
}

void CerfVirtCustomizationsReset::OnCustomizationsApplied() {
    if (applied_) return;
    applied_ = true;
    LOG(GuestAdditions,
        "registry customizations committed - soft-resetting the guest so GWES "
        "re-reads them\n");
    emu_.Get<BootScreen>().SetRestartLabel(L"Applying customizations...");
    emu_.Get<GuestCpuReset>().WarmReset();
}

void CerfVirtCustomizationsReset::Invalidate() {
    if (!applied_) return;
    applied_ = false;
    LOG(GuestAdditions, "customizations changed - the next boot re-applies them\n");
}

void CerfVirtCustomizationsReset::SaveState(StateWriter& w) const {
    w.Write<uint32_t>(applied_ ? 1u : 0u);
}

void CerfVirtCustomizationsReset::RestoreState(StateReader& r) {
    uint32_t v = 0;
    r.Read(v);
    applied_ = (v != 0u);
}
