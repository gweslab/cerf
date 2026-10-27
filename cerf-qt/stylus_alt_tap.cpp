#include "stylus_alt_tap.h"

#include "frontend_window.h"
#include "host_virtual_keys.h"

#include <cerfcore/core/cerf_emulator.h>
#include <cerfcore/core/device_config.h>
#include <cerfcore/host/keyboard_input.h>
#include <cerfcore/host/keyboard_map.h>
#include <cerfcore/host/keyboard_router.h>
#include <cerfcore/host/touch_input.h>
#include <cerfcore/state/emulation_freeze.h>
#include <cerfcore/state/state_stream.h>

namespace cerffrontend {

REGISTER_SERVICE(StylusAltTap);

namespace {

constexpr uint32_t kAltLeadMs  = 500;
constexpr uint32_t kPenHoldMs  = 150;
constexpr uint32_t kAltTrailMs = 150;

}

bool StylusAltTap::Supported() const {
    if (!emu_.TryGet<cerfcore::TouchInput>()) return false;
    if (emu_.Get<cerfcore::DeviceConfig>().guest_additions) return true;
    auto*    map = emu_.TryGet<cerfcore::KeyboardMap>();
    uint32_t code;
    return map && map->BaseDeviceCode(kVkMenu, code);
}

bool StylusAltTap::Armable() const {
    if (!Supported()) return false;
    cerfcore::KeyboardInput* kbd = emu_.Get<cerfcore::KeyboardRouter>().Active();
    return kbd && kbd->CanDeliverVk(kVkMenu);
}

void StylusAltTap::Arm(uint32_t ms, Phase next) {
    SetPhase(next);
    const uint32_t gen = timer_gen_.fetch_add(1u, std::memory_order_acq_rel) + 1u;
    emu_.Get<FrontendWindow>().RunOnUiThreadAfter(ms, [this, gen] { OnTimer(gen); });
}

void StylusAltTap::UnwindHeld() {
    if (CurrentPhase() == Phase::Idle) return;
    Disarm();
    const bool pen_down = CurrentPhase() == Phase::PenHold;
    SetPhase(Phase::Idle);
    if (pen_down) emu_.Get<cerfcore::TouchInput>().OnPenUp(tap_x_, tap_y_);
    emu_.Get<cerfcore::KeyboardRouter>().OnHostKey(kVkMenu, true);
}

bool StylusAltTap::Begin(int guest_x, int guest_y) {
    if (!Enabled() || !Armable()) return false;
    if (CurrentPhase() != Phase::Idle) return true;
    auto freeze = emu_.Get<cerfcore::EmulationFreeze>().WorkerSection();
    tap_x_ = guest_x;
    tap_y_ = guest_y;
    emu_.Get<cerfcore::KeyboardRouter>().OnHostKey(kVkMenu, false);
    Arm(kAltLeadMs, Phase::AltLead);
    return true;
}

void StylusAltTap::OnTimer(uint32_t gen) {
    if (gen != timer_gen_.load(std::memory_order_acquire) || CurrentPhase() == Phase::Idle)
        return;
    auto freeze = emu_.Get<cerfcore::EmulationFreeze>().WorkerSection();
    Disarm();
    switch (CurrentPhase()) {
        case Phase::AltLead:
            emu_.Get<cerfcore::TouchInput>().OnPenDown(tap_x_, tap_y_);
            Arm(kPenHoldMs, Phase::PenHold);
            return;
        case Phase::PenHold:
            emu_.Get<cerfcore::TouchInput>().OnPenUp(tap_x_, tap_y_);
            Arm(kAltTrailMs, Phase::AltTrail);
            return;
        case Phase::AltTrail:
            SetPhase(Phase::Idle);
            emu_.Get<cerfcore::KeyboardRouter>().OnHostKey(kVkMenu, true);
            return;
        case Phase::Idle:
            return;
    }
}

void StylusAltTap::Cancel() {
    if (CurrentPhase() == Phase::Idle) return;
    auto freeze = emu_.Get<cerfcore::EmulationFreeze>().WorkerSection();
    UnwindHeld();
}

void StylusAltTap::SaveState(cerfcore::StateWriter& w) const {
    w.Write<uint8_t>("phase", static_cast<uint8_t>(CurrentPhase()));
    w.Write<int32_t>("tap_x", tap_x_);
    w.Write<int32_t>("tap_y", tap_y_);
}

void StylusAltTap::RestoreState(cerfcore::StateReader& r) {
    uint8_t raw = 0;
    int32_t x = 0, y = 0;
    r.Read("phase", raw);
    r.Read("tap_x", x);
    r.Read("tap_y", y);
    const Phase saved = raw <= static_cast<uint8_t>(Phase::AltTrail) ? static_cast<Phase>(raw)
                                                                      : Phase::Idle;
    const uint32_t gen = restore_gen_.fetch_add(1u, std::memory_order_acq_rel) + 1u;
    if (saved == Phase::Idle && CurrentPhase() == Phase::Idle) return;
    emu_.Get<FrontendWindow>().RunOnUiThread([this, saved, x, y, gen] {
        auto freeze = emu_.Get<cerfcore::EmulationFreeze>().WorkerSection();
        if (restore_gen_.load(std::memory_order_acquire) != gen) return;
        Disarm();
        SetPhase(Phase::Idle);
        if (saved == Phase::Idle) return;
        if (saved == Phase::PenHold) emu_.Get<cerfcore::TouchInput>().OnPenUp(x, y);
        emu_.Get<cerfcore::KeyboardRouter>().OnHostKey(kVkMenu, true);
    });
}

void StylusAltTap::OnShutdown() {
    auto freeze = emu_.Get<cerfcore::EmulationFreeze>().WorkerSection();
    if (CurrentPhase() == Phase::Idle) return;
    Disarm();
    SetPhase(Phase::Idle);
}

}
