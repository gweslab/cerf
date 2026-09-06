#include "stylus_alt_tap.h"

#include "../core/cerf_emulator.h"
#include "../core/device_config.h"
#include "../core/log.h"
#include "../state/emulation_freeze.h"
#include "../state/state_stream.h"
#include "host_canvas.h"
#include "host_window.h"
#include "keyboard_input.h"
#include "keyboard_map.h"
#include "keyboard_router.h"
#include "touch_input.h"

REGISTER_SERVICE(StylusAltTap);

namespace {

constexpr UINT_PTR kTimerId    = 0x5A17;
constexpr UINT     kAltLeadMs  = 500;
constexpr UINT     kPenHoldMs  = 150;
constexpr UINT     kAltTrailMs = 150;
constexpr uint8_t  kVkAlt      = 0x12;

}  /* namespace */

bool StylusAltTap::Supported() const {
    if (!emu_.TryGet<TouchInput>()) return false;
    if (emu_.Get<DeviceConfig>().guest_additions) return true;
    auto* map = emu_.TryGet<KeyboardMap>();
    uint32_t code;
    return map && map->BaseDeviceCode(kVkAlt, code);
}

bool StylusAltTap::Armable() const {
    if (!Supported()) return false;
    KeyboardInput* kbd = emu_.Get<KeyboardRouter>().Active();
    return kbd && kbd->CanDeliverVk(kVkAlt);
}

void StylusAltTap::Arm(UINT ms, Phase next) {
    SetPhase(next);
    if (SetTimer(emu_.Get<HostCanvas>().Hwnd(), kTimerId, ms, nullptr) != 0) return;
    LOG(Caution, "StylusAltTap: SetTimer failed (gle=%lu), phase=%d\n",
        GetLastError(), static_cast<int>(next));
    UnwindHeld();
}

void StylusAltTap::UnwindHeld() {
    if (CurrentPhase() == Phase::Idle) return;
    KillTimer(emu_.Get<HostCanvas>().Hwnd(), kTimerId);
    const bool pen_down = CurrentPhase() == Phase::PenHold;
    SetPhase(Phase::Idle);
    if (pen_down) emu_.Get<TouchInput>().OnPenUp(tap_x_, tap_y_);
    emu_.Get<KeyboardRouter>().OnHostKey(kVkAlt, /*key_up=*/true);
}

bool StylusAltTap::Begin(int guest_x, int guest_y) {
    if (!Enabled() || !Armable()) return false;
    if (CurrentPhase() != Phase::Idle) return true;
    auto freeze = emu_.Get<EmulationFreeze>().WorkerSection();
    tap_x_ = guest_x;
    tap_y_ = guest_y;
    emu_.Get<KeyboardRouter>().OnHostKey(kVkAlt, /*key_up=*/false);
    Arm(kAltLeadMs, Phase::AltLead);
    return true;
}

bool StylusAltTap::OnTimer(UINT_PTR timer_id) {
    if (timer_id != kTimerId || CurrentPhase() == Phase::Idle) return false;
    auto freeze = emu_.Get<EmulationFreeze>().WorkerSection();
    KillTimer(emu_.Get<HostCanvas>().Hwnd(), kTimerId);
    switch (CurrentPhase()) {
        case Phase::AltLead:
            emu_.Get<TouchInput>().OnPenDown(tap_x_, tap_y_);
            Arm(kPenHoldMs, Phase::PenHold);
            return true;
        case Phase::PenHold:
            emu_.Get<TouchInput>().OnPenUp(tap_x_, tap_y_);
            Arm(kAltTrailMs, Phase::AltTrail);
            return true;
        case Phase::AltTrail:
            SetPhase(Phase::Idle);
            emu_.Get<KeyboardRouter>().OnHostKey(kVkAlt, /*key_up=*/true);
            return true;
        case Phase::Idle:
            return true;
    }
    return true;
}

void StylusAltTap::Cancel() {
    if (CurrentPhase() == Phase::Idle) return;
    auto freeze = emu_.Get<EmulationFreeze>().WorkerSection();
    UnwindHeld();
}

void StylusAltTap::SaveState(StateWriter& w) const {
    w.Write<uint8_t>(static_cast<uint8_t>(CurrentPhase()));
    w.Write<int32_t>(tap_x_);
    w.Write<int32_t>(tap_y_);
}

void StylusAltTap::RestoreState(StateReader& r) {
    uint8_t raw = 0;
    int32_t x = 0, y = 0;
    r.Read(raw);
    r.Read(x);
    r.Read(y);
    const Phase saved = raw <= static_cast<uint8_t>(Phase::AltTrail)
                        ? static_cast<Phase>(raw) : Phase::Idle;
    if (saved == Phase::Idle && CurrentPhase() == Phase::Idle) return;
    emu_.Get<HostWindow>().RunOnUiThread([this, saved, x, y] {
        auto freeze = emu_.Get<EmulationFreeze>().WorkerSection();
        KillTimer(emu_.Get<HostCanvas>().Hwnd(), kTimerId);
        SetPhase(Phase::Idle);
        if (saved == Phase::Idle) return;
        if (saved == Phase::PenHold) emu_.Get<TouchInput>().OnPenUp(x, y);
        emu_.Get<KeyboardRouter>().OnHostKey(kVkAlt, /*key_up=*/true);
    });
}

void StylusAltTap::OnShutdown() {
    auto freeze = emu_.Get<EmulationFreeze>().WorkerSection();
    if (CurrentPhase() == Phase::Idle) return;
    KillTimer(emu_.Get<HostCanvas>().Hwnd(), kTimerId);
    SetPhase(Phase::Idle);
}
