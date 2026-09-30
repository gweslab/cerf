#include "sa1111_reset_line.h"

#include "../../core/cerf_emulator.h"
#include "../../core/fatal.h"
#include "../../socs/guest_cpu_reset.h"
#include "../../boards/board_context.h"
#include "../../boards/jornada720/jornada_720_id.h"
#include "../../state/state_stream.h"

namespace {

/* SA-1111 Developer's Manual §5.1.1 (printed 5-1): "RAB (24 MHz RCLK)". Figure 2-2 (printed
   2-5): nBRES rises 12 RCLK and then 2 RCLK after RCLKEn. */
constexpr uint64_t kRclkHz            = 24000000u;
constexpr uint64_t kReleaseRclkCycles = 14u;

constexpr Sa1111SerialTransfer::Keys kReleaseKeys = {
    "nbres_release_busy", "nbres_release_rclk", "nbres_release_elapsed",
    "nbres_release_phase", "nbres_release_phase_den"};

}

Sa1111ResetLine::Sa1111ResetLine(CerfEmulator& emu)
    : Service(emu), release_(emu, "Sa1111ResetLine", kRclkHz, kReleaseKeys) {}

bool Sa1111ResetLine::ShouldRegister() {
    auto* bd = emu_.TryGet<BoardContext>();
    return bd && bd->GetBoardId() == BoardId::Jornada720;
}

void Sa1111ResetLine::OnReady() {
    clock_ = &emu_.Get<GuestCycleClock>();
    release_.Attach();
    auto& reset = emu_.Get<GuestCpuReset>();
    reset.RegisterResetListener([this](ResetLineKind kind) {
        power_on_pending_ = kind == ResetLineKind::Rtc;
    });
    reset.RegisterResetReleaseListener([this] {
        if (!power_on_pending_) return;
        power_on_pending_ = false;
        Assert();
    });
}

void Sa1111ResetLine::RegisterListener(std::function<void(bool held)> fn) {
    listeners_.push_back(std::move(fn));
}

void Sa1111ResetLine::Assert() {
    SettleRelease();
    if (release_pending_) {
        emu_.Get<Fatal>().Die("Sa1111ResetLine: nRESET asserted while nBRES release is pending "
                              "is not modelled");
    }
    if (Held()) return;
    held_.store(true, std::memory_order_release);
    for (auto& fn : listeners_) fn(true);
}

/* SA-1111 Developer's Manual §2.3: "When nRESET is asserted, all on-chip activity halts;
   when nRESET is released, the SA-1111 goes to doze mode". */
void Sa1111ResetLine::Drive(Pin level, bool resync) {
    if (!resync) SettleRelease();
    if (!resync && release_pending_ && level != Pin::High) {
        emu_.Get<Fatal>().Die("Sa1111ResetLine: nRESET leaving High while nBRES release is "
                              "pending is not modelled");
    }
    pin_ = level;
    if (!resync && level == Pin::Low) Assert();
}

/* SA-1111 Developer's Manual Figure 2-2 (printed 2-5): nBRES stays asserted after nRESET
   rises and rises after RCLKEn. */
void Sa1111ResetLine::OnSkcrWrite(bool rclk_enabled, bool pll_selected) {
    SettleRelease();
    if (release_pending_) {
        if (rclk_enabled && pll_selected) return;
        emu_.Get<Fatal>().Die("Sa1111ResetLine: SKCR leaving RCLKEn or the PLL while nBRES "
                              "release is pending is not modelled");
    }
    if (!rclk_enabled || pin_ != Pin::High || !Held()) return;
    if (!pll_selected) {
        emu_.Get<Fatal>().Die("Sa1111ResetLine: SKCR RCLKEn set with the PLL bypassed, the VCO "
                              "off or no 3.6864 MHz CLK input during reset is not modelled");
    }
    release_.Start(clock_->Cycles(), kReleaseRclkCycles);
    release_pending_ = true;
}

void Sa1111ResetLine::SettleRelease() {
    if (!release_pending_ || release_.Busy(clock_->Cycles())) return;
    release_pending_ = false;
    release_.Clear();
    Release();
}

void Sa1111ResetLine::Release() {
    held_.store(false, std::memory_order_release);
    for (auto& fn : listeners_) fn(false);
}

void Sa1111ResetLine::SaveState(StateWriter& w) {
    w.Write<uint8_t>("nreset_held", Held() ? 1u : 0u);
    w.Write<uint8_t>("nbres_release_pending", release_pending_ ? 1u : 0u);
    release_.Save(w, clock_->Cycles());
}

void Sa1111ResetLine::RestoreState(StateReader& r) {
    uint8_t held = 0u, pending = 0u;
    r.Read("nreset_held", held);
    r.Read("nbres_release_pending", pending);
    release_.Restore(r, clock_->Cycles());
    held_.store(held != 0u, std::memory_order_release);
    release_pending_ = pending != 0u;
}

void Sa1111ResetLine::RequireReleased(const char* unit, uint32_t addr) const {
    if (pin_ == Pin::High) return;
    emu_.Get<Fatal>().Die("%s: access at 0x%08X with the SA-1111 nRESET %s is not modelled",
                          unit, addr, pin_ == Pin::Low ? "asserted" : "floating");
}

REGISTER_SERVICE(Sa1111ResetLine);
