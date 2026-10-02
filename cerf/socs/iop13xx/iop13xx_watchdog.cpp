#include "iop13xx_watchdog.h"

#include "iop13xx_clocks.h"
#include "iop13xx_id.h"
#include "../../boards/board_context.h"
#include "../../core/cerf_emulator.h"
#include "../../core/fatal.h"
#include "../../state/state_stream.h"
#include "../guest_cpu_reset.h"
#include "../irq_controller.h"

namespace {

/* Intel 81341/81342 Developer's Manual section 12.4.6 (printed p. 819): 1E1E1E1EH then E1E1E1E1H enables or
   reinitializes the WDT to FFFFFFFFH; 1F1F1F1FH then F1F1F1F1H disables it. */
constexpr uint32_t kEnableArm    = 0x1E1E1E1Eu;
constexpr uint32_t kEnable       = 0xE1E1E1E1u;
constexpr uint32_t kDisableArm   = 0x1F1F1F1Fu;
constexpr uint32_t kDisable      = 0xF1F1F1F1u;
constexpr uint64_t kInitialCount = 0xFFFFFFFFull;

/* Table 502 (printed p. 819): WDTSR [0] 0 = interrupt, 1 = reset;
   [31] preserved, [30:1] reserved. */
constexpr uint32_t kSetupReset = 1u << 0;

/* Table 467 (printed p. 768): INTCTL0 bit 6 is the watch dog timer. */
constexpr int kWatchdogSource = 6;

}

bool Iop13xxWatchdog::ShouldRegister() {
    auto* bd = emu_.TryGet<BoardContext>();
    return bd && bd->GetSocId() == SocId::Iop13xx;
}

void Iop13xxWatchdog::OnReady() {
    clock_ = &emu_.Get<GuestCycleClock>();
    event_ = clock_->Add([this] { OnEvent(); });
    ResetState();
    emu_.Get<GuestCpuReset>().RegisterResetListener([this](ResetLineKind) {
        if (emu_.Get<GuestCpuReset>().DeliveredResetWasResume()) return;
        ResetState();
    });
}

void Iop13xxWatchdog::SetBusRatio() {
    if (!counter_.SetRatio(kIop13xxCoreCyclesPerBusClock, 1u)) {
        emu_.Get<Fatal>().Die("IOP13xx WDT: %llu core cycles per bus clock overflow the cycle ratio",
                              static_cast<unsigned long long>(kIop13xxCoreCyclesPerBusClock));
    }
}

/* Section 12.4.6 (printed p. 819): WDTCR decrements with each internal bus
   clock tick; at terminal count WDTSR selects an internal bus reset or a TISR
   interrupt. */
void Iop13xxWatchdog::Advance(uint64_t cycle) {
    if (!enabled_ || expired_) return;
    if (counter_.TicksSince(cycle) < terminal_) return;
    expired_ = true;
    if ((setup_ & kSetupReset) == 0u) {
        pending_ = true;
        return;
    }
    enabled_ = false;
    emu_.Get<GuestCpuReset>().WatchdogReset();
}

void Iop13xxWatchdog::Arm() {
    if (!enabled_ || expired_ || (pending_ && (setup_ & kSetupReset) == 0u)) {
        clock_->Disarm(event_);
        return;
    }
    clock_->Arm(event_, counter_.CycleOfTick(terminal_));
}

/* Table 501 (printed p. 819): WDTCR resets to 0 and reads the current count. */
uint32_t Iop13xxWatchdog::ReadControl() {
    const uint64_t now = clock_->Cycles();
    Advance(now);
    PublishLevel();
    if (!ever_enabled_) return 0u;
    if (!enabled_ || expired_) {
        emu_.Get<Fatal>().Die("IOP13xx WDTCR read after the WDT %s; that count is not "
                              "documented", expired_ ? "reached terminal count"
                                                     : "was disabled");
    }
    return static_cast<uint32_t>(terminal_ - counter_.TicksSince(now));
}

void Iop13xxWatchdog::WriteControl(uint32_t value) {
    const uint64_t now = clock_->Cycles();
    Advance(now);
    PublishLevel();
    if (value == kEnableArm && !disable_armed_) {
        enable_armed_ = true;
        return;
    }
    if (value == kEnable && enable_armed_) {
        SetBusRatio();
        counter_.Anchor(now, 0u);
        terminal_     = kInitialCount;
        enable_armed_ = false;
        enabled_      = true;
        ever_enabled_ = true;
        expired_      = false;
        Arm();
        return;
    }
    if (value == kDisableArm && enabled_ && !enable_armed_) {
        disable_armed_ = true;
        return;
    }
    if (value == kDisable && disable_armed_) {
        disable_armed_ = false;
        enabled_       = false;
        Arm();
        return;
    }
    emu_.Get<Fatal>().Die("IOP13xx WDTCR write 0x%08X is outside the documented sequences "
                          "(enabled %d, enable armed %d, disable armed %d)", value,
                          enabled_ ? 1 : 0, enable_armed_ ? 1 : 0, disable_armed_ ? 1 : 0);
}

void Iop13xxWatchdog::WriteSetup(uint32_t value) {
    if ((value & ~kSetupReset) != 0u) {
        emu_.Get<Fatal>().Die("IOP13xx WDTSR write 0x%08X sets bits [31:1]", value);
    }
    Advance(clock_->Cycles());
    PublishLevel();
    setup_ = value;
    Arm();
}

/* Table 500 (printed p. 818): TISR [2] is the watchdog interrupt pending bit;
   software writes 1 to clear it. */
void Iop13xxWatchdog::ClearPending() {
    Advance(clock_->Cycles());
    pending_ = false;
    Arm();
    PublishLevel();
}

void Iop13xxWatchdog::OnEvent() {
    Advance(clock_->Cycles());
    PublishLevel();
}

/* Section 12.1.2 (printed p. 809): the WDT is disabled after P_RST#;
   section 12.4.5 (printed p. 818): TISR clears on reset; Tables 501-502 reset
   WDTCR and WDTSR to 0. */
void Iop13xxWatchdog::ResetState() {
    enabled_       = false;
    enable_armed_  = false;
    disable_armed_ = false;
    expired_       = false;
    ever_enabled_  = false;
    pending_       = false;
    published_     = false;
    setup_         = 0;
    terminal_      = 0;
    clock_->Disarm(event_);
}

void Iop13xxWatchdog::PublishLevel() {
    if (pending_ == published_) return;
    if (pending_)
        emu_.Get<IrqController>().AssertIrq(kWatchdogSource);
    else
        emu_.Get<IrqController>().DeAssertIrq(kWatchdogSource);
    published_ = pending_;
}

void Iop13xxWatchdog::SaveState(StateWriter& w) {
    const uint64_t now = clock_->Cycles();
    Advance(now);
    const bool live = enabled_ && !expired_;
    w.Write("wdt_enabled", enabled_);
    w.Write("wdt_enable_armed", enable_armed_);
    w.Write("wdt_disable_armed", disable_armed_);
    w.Write("wdt_expired", expired_);
    w.Write("wdt_ever_enabled", ever_enabled_);
    w.Write("wdt_pending", pending_);
    w.Write("wdt_setup", setup_);
    w.Write<uint64_t>("wdt_remaining", live ? terminal_ - counter_.TicksSince(now) : 0u);
    w.Write<uint64_t>("wdt_phase", live ? counter_.PhaseAt(now) : 0u);
    w.Write<uint64_t>("wdt_phase_den", counter_.PhaseDenominator());
}

void Iop13xxWatchdog::RestoreState(StateReader& r) {
    const uint64_t now       = clock_->Cycles();
    uint64_t       remaining = 0, phase = 0, phase_den = 1;
    r.Read("wdt_enabled", enabled_);
    r.Read("wdt_enable_armed", enable_armed_);
    r.Read("wdt_disable_armed", disable_armed_);
    r.Read("wdt_expired", expired_);
    r.Read("wdt_ever_enabled", ever_enabled_);
    r.Read("wdt_pending", pending_);
    r.Read("wdt_setup", setup_);
    r.Read("wdt_remaining", remaining);
    r.Read("wdt_phase", phase);
    r.Read("wdt_phase_den", phase_den);
    terminal_ = 0;
    if (enabled_ && !expired_) {
        SetBusRatio();
        counter_.AnchorAtPhase(now, 0u, phase, phase_den);
        terminal_ = remaining;
    }
    Arm();
}

void Iop13xxWatchdog::PostRestore() {
    published_ = !pending_;
    PublishLevel();
}

REGISTER_SERVICE(Iop13xxWatchdog);
