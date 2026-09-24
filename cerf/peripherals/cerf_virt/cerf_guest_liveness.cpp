#include "cerf_guest_liveness.h"

#include "../../core/cerf_emulator.h"
#include "../../core/device_config.h"
#include "../../core/log.h"
#include "../../host/keyboard_router.h"
#include "../../host/pointer_router.h"
#include "../../socs/guest_cpu_reset.h"
#include "../../state/state_stream.h"

REGISTER_SERVICE(CerfGuestLiveness);

bool CerfGuestLiveness::ShouldRegister() {
    return emu_.Get<DeviceConfig>().guest_additions;
}

void CerfGuestLiveness::OnReady() {
    emu_.Get<GuestCpuReset>().RegisterResetListener([this](ResetLineKind) {
        if (!emu_.Get<GuestCpuReset>().DeliveredResetWasResume()) Clear();
    });
}

void CerfGuestLiveness::NotifyBodyFetch() {
    if (alive_.load(std::memory_order_acquire)) return;
    if (alive_.exchange(true, std::memory_order_acq_rel)) return;
    LOG(GuestAdditions, "guest additions: driver body fetched, guest is alive - "
        "switching host input to the guest additions sources\n");
    emu_.Get<KeyboardRouter>().ReevaluateAuto();
    emu_.Get<PointerRouter>().ReevaluateAuto();
}

void CerfGuestLiveness::SaveState(StateWriter& w) const {
    w.Write<uint8_t>("alive", alive_.load(std::memory_order_acquire) ? 1u : 0u);
}

void CerfGuestLiveness::RestoreState(StateReader& r) {
    uint8_t v = 0;
    r.Read("alive", v);
    alive_.store(v != 0, std::memory_order_release);
}

void CerfGuestLiveness::Clear() {
    alive_.store(false, std::memory_order_release);
    LOG(GuestAdditions, "guest additions: guest reset, host input returns to "
        "the stock sources until the driver body is fetched again\n");
    emu_.Get<KeyboardRouter>().RearmAutoSelect();
    emu_.Get<PointerRouter>().RearmAutoSelect();
}
