#include "vr4122_clock_state.h"

#include "../../boards/board_context.h"
#include "vr4122_id.h"
#include "../../core/cerf_emulator.h"
#include "../../core/fatal.h"
#include "../../jit/mips/mips_core_clock.h"
#include "../../state/state_stream.h"
#include "../guest_cpu_reset.h"
#include "../vr41xx/vr41xx_clock_strap.h"

REGISTER_SERVICE(Vr4122ClockState);

namespace {

struct ClkselRow {
    uint16_t clksp;
    uint16_t vtdiv;
};

/* VR4122 data sheet U15585EJ1V0DS Table 1-1 p.11, PClock = CLKX / CLKSP x 98
   (NetBSD hpcmips vrbcu_vrip_getcpuclock); CLKSEL 111 RFU. */
constexpr ClkselRow kClksel[8] = {
    {23u, 3u}, {20u, 3u}, {18u, 3u}, {14u, 4u}, {12u, 5u}, {11u, 5u}, {10u, 6u}, {0u, 0u},
};

constexpr uint64_t kPClockMult = 98u;
constexpr uint16_t kVtDivMask = 0x7u;
constexpr uint16_t kVtDivRfu1 = 0x1u;
constexpr uint16_t kVtDivRfu7 = 0x7u;
constexpr uint16_t kTDivShift = 8u;
constexpr uint64_t kTClockPerMasterOut = 4u;

}

bool Vr4122ClockState::ShouldRegister() {
    auto* bd = emu_.TryGet<BoardContext>();
    return bd && bd->GetSocId() == SocId::Vr4122;
}

void Vr4122ClockState::OnReady() {
    const ClkselRow& row = emu_.Get<Vr41xxClockStrap>().StrapRow(kClksel);
    clksp_       = row.clksp;
    strap_vtdiv_ = row.vtdiv;
    emu_.Get<GuestCpuReset>().RegisterResetListener([this](ResetLineKind kind) {
        if (kind == ResetLineKind::Rtc) { pending_ = 0; active_ = 0; }
        else                            { active_ = pending_; }
    });
}

void Vr4122ClockState::SetPending(uint16_t tclkdiv) { pending_ = tclkdiv; }

uint16_t Vr4122ClockState::VtDivMode() const {
    const uint16_t vtdiv = active_ & kVtDivMask;
    if (vtdiv == kVtDivRfu1 || vtdiv == kVtDivRfu7) {
        emu_.Get<Fatal>().Die("Vr4122ClockState: PMUTCLKDIVREG VTDIV %u is RFU", vtdiv);
    }
    return vtdiv != 0u ? vtdiv : strap_vtdiv_;
}

uint16_t Vr4122ClockState::TDivMode() const {
    if ((active_ & kVtDivMask) == 0u) return 0u;
    return static_cast<uint16_t>((active_ >> kTDivShift) & 1u);
}

uint16_t Vr4122ClockState::ClkSpeedReg() const {
    return static_cast<uint16_t>((TDivMode() << 12) | (VtDivMode() << 8) | clksp_);
}

GuestCycleClock::Rate Vr4122ClockState::ResetRate() const {
    return GuestCycleClock::Rate{kVr41xxClkxHz * kPClockMult, clksp_};
}

uint64_t Vr4122ClockState::CyclesPerCountTick() const {
    const uint64_t tclk_per_vtclk = TDivMode() != 0u ? 4u : 2u;
    return uint64_t{VtDivMode()} * tclk_per_vtclk * kTClockPerMasterOut;
}

/* "The countdown uses a VTClock cycle" (VR4131 UM U15350EJ2V0UM 13.2.8 p253). */
uint64_t Vr4122ClockState::CyclesPerTclkCounterTick() const {
    return VtDivMode();
}

void Vr4122ClockState::SaveState(StateWriter& w) const {
    w.Write("pending", pending_);
    w.Write("active", active_);
}
void Vr4122ClockState::RestoreState(StateReader& r) {
    r.Read("pending", pending_);
    r.Read("active", active_);
    emu_.Get<MipsCoreClock>().CountRateRestored();
}
