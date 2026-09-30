#include "sa1111_sbi.h"

#include "../../core/cerf_emulator.h"
#include "../../core/fatal.h"
#include "../../core/log.h"
#include "../../boards/board_context.h"
#include "../../boards/jornada720/jornada_720_id.h"
#include "../../state/state_stream.h"
#include "sa1111_reset_line.h"
#include "sa1111_system_controller.h"

bool Sa1111Sbi::ShouldRegister() {
    auto* bd = emu_.TryGet<BoardContext>();
    return bd && bd->GetBoardId() == BoardId::Jornada720;
}

/* SA-1111 Developer's Manual §2.3: "Unless indicated otherwise, all register bits are set
   to zero during reset." */
void Sa1111Sbi::OnChipReset(bool held) {
    if (!held) return;
    skcr_ = kSkcrReset;
    smcr_ = kSmcrReset;
    if (clock_disturbed_) LOG(Periph, "[Sa1111Sbi] CLK disturbance cleared by the chip reset\n");
    clock_disturbed_ = false;
}

/* SA-1111 Developer's Manual Table 1-1 (printed 1-4 / 1-6): MBGNT "Memory bus grant, from SA-1110
   processor"; CLK "Master clock in, 3.6864 MHz. Connect to SA-1110 GPIO<27>." */
void Sa1111Sbi::SetHostPins(std::function<Mbgnt()> mbgnt, std::function<bool()> clk_3686400) {
    mbgnt_       = std::move(mbgnt);
    clk_3686400_ = std::move(clk_3686400);
    clk_seen_    = LiveClockInput();
}

bool Sa1111Sbi::LiveClockInput() const {
    return clk_3686400_ && clk_3686400_();
}

bool Sa1111Sbi::ClockInputModelled() const {
    return clk_seen_;
}

/* §2.2 (printed 2-3): "A phase-locked loop (PLL) in the SA-1111 generates the clocks required for
   its I/O functions and internal systems. The input clock goes to the PLL's phase comparator." */
bool Sa1111Sbi::PllClockSelected() const {
    return (skcr_ & kSkcrPllBypass) != 0u && (skcr_ & kSkcrVcoOff) == 0u && ClockInputModelled();
}

void Sa1111Sbi::OnHostPinsChange() {
    const bool clk = LiveClockInput();
    if (clk != clk_seen_) {
        const bool disturb = !ChipHeld() && !clock_disturbed_;
        if (disturb) {
            for (auto& fn : clk_input_listeners_) fn();
        }
        clk_seen_ = clk;
        if (disturb) {
            clock_disturbed_ = true;
            LOG(Periph, "[Sa1111Sbi] CLK input %s outside reset (SKCR 0x%08X)\n",
                clk ? "restored" : "lost", skcr_);
        }
    }
    NotifyGrant();
}

void Sa1111Sbi::RegisterGrantListener(std::function<void()> fn) {
    grant_listeners_.push_back(std::move(fn));
}

void Sa1111Sbi::RegisterClkInputListener(std::function<void()> fn) {
    clk_input_listeners_.push_back(std::move(fn));
}

void Sa1111Sbi::NotifyGrant() {
    for (auto& fn : grant_listeners_) fn();
}

/* Table 3-10 MBGE: "0=MBGNT is gated and disabled. 1=MBGNT is enabled."; Figure 3-7 (printed
   3-13): MBGNT high for the whole bus tenure. */
Sa1111Sbi::BusGrant Sa1111Sbi::Grant() const {
    if ((smcr_ & kSmcrMbge) == 0u) return BusGrant::Stalled;
    switch (mbgnt_ ? mbgnt_() : Mbgnt::Undetermined) {
        case Mbgnt::Arbiter: return BusGrant::Granted;
        case Mbgnt::Low:     return BusGrant::Stalled;
        case Mbgnt::High:
        case Mbgnt::Undetermined: break;
    }
    return BusGrant::Undetermined;
}

/* SA-1111 Developer's Manual §2.4.3 State 5 (printed 2-8): "This state is entered from
   sleep mode anytime nCS goes active (any read or write to SA-1111)." */
void Sa1111Sbi::RequireAwake(uint32_t addr) const {
    if (!SleepRequested()) return;
    emu_.Get<Fatal>().Die("Sa1111Sbi: access at 0x%08X with SKCR Sleep set (the Sleep Mode "
                          "wake-up) is not modelled", addr);
}

/* SA-1111 Developer's Manual §2.4.2 (printed 2-6): "If RCLK is turned off, only the
   latch-based Control Register (SKCR) in SBI block can be accessed." */
void Sa1111Sbi::RequireRclk(uint32_t addr) const {
    if (!BusClocksEnabled()) {
        emu_.Get<Fatal>().Die("Sa1111Sbi: access at 0x%08X with SKCR RCLKEn clear (0x%08X) is not "
                              "modelled", addr, skcr_);
    }
    if (clock_disturbed_) {
        emu_.Get<Fatal>().Die("Sa1111Sbi: access at 0x%08X after the CLK input changed outside "
                              "reset is not modelled", addr);
    }
}

uint32_t Sa1111Sbi::UnitReadWord(uint32_t addr) {
    RequireAwake(addr);
    switch (addr - MmioBase()) {
        case 0x00: return skcr_;
        case 0x04: RequireRclk(addr); return smcr_;
        case 0x08: RequireRclk(addr); return 0x690CC200u;
    }
    HaltUnsupportedAccess("ReadWord", addr, 0);
}

void Sa1111Sbi::UnitWriteWord(uint32_t addr, uint32_t value) {
    RequireAwake(addr);
    switch (addr - MmioBase()) {
        case 0x00:
            skcr_ = value & kSkcrDefined;
            emu_.Get<Sa1111ResetLine>().OnSkcrWrite(BusClocksEnabled(), PllClockSelected());
            emu_.Get<Sa1111SystemController>().NotifyClockListeners();
            return;
        case 0x04:
            RequireRclk(addr);
            /* §3.2.3.5: "Bit 0 of the SMC Control Register (DTIM) must always be programmed
               with a one." */
            if ((value & kSmcrDtim) == 0u) {
                emu_.Get<Fatal>().Die("Sa1111Sbi: SMCR 0x%08X with DTIM clear is not modelled",
                                      value);
            }
            smcr_ = value & kSmcrDefined;
            emu_.Get<Sa1111SystemController>().NotifyClockListeners();
            NotifyGrant();
            return;
    }
    HaltUnsupportedAccess("WriteWord", addr, value);
}

/* SA-1110 §10.8: SDCKE 1 re-asserted at t + 4 Tmem, "Tmem ... (twice the CPU clock period)".
   SA-1111 Table 4-4: SacReq set up to the rising edge of DCLK; §3.2.3.1 / Figure 3-7: Activ,
   Wait, one Read per word, data after the programmed CAS latency. */
uint64_t Sa1111Sbi::BurstWordCycles(uint32_t word, uint64_t cpu_hz, uint32_t cas) const {
    const uint64_t sdclks = 1u + 2u + static_cast<uint64_t>(word) + cas;
    return 8u + (sdclks * cpu_hz + kSdclkHz - 1u) / kSdclkHz;
}

/* SA-1110 §10.8 release: "SA-1110 asserts SDCKE 1 at time (t + 4*Tmem)"; the grant then begins
   when the SA-1110 "deasserts SDCKE 1". */
uint64_t Sa1111Sbi::BusReleaseCycles() const {
    return 8u;
}

void Sa1111Sbi::SaveState(StateWriter& w) {
    w.Write("skcr", skcr_);
    w.Write("smcr", smcr_);
    w.Write<uint8_t>("clk_disturbed", clock_disturbed_ ? 1u : 0u);
    emu_.Get<Sa1111ResetLine>().SaveState(w);
}

void Sa1111Sbi::RestoreState(StateReader& r) {
    r.Read("skcr", skcr_);
    r.Read("smcr", smcr_);
    uint8_t disturbed = 0u;
    r.Read("clk_disturbed", disturbed);
    clock_disturbed_ = disturbed != 0u;
    emu_.Get<Sa1111ResetLine>().RestoreState(r);
}

void Sa1111Sbi::PostRestore() {
    clk_seen_ = LiveClockInput();
}

REGISTER_SERVICE(Sa1111Sbi);
