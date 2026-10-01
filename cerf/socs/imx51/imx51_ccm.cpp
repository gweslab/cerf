#include "imx51_ccm.h"

#include "../../boards/board_context.h"
#include "../../core/cerf_emulator.h"
#include "../../core/fatal.h"
#include "../../core/log.h"
#include "../../jit/guest_cycle_clock.h"
#include "../../peripherals/peripheral_dispatcher.h"
#include "../../state/state_stream.h"
#include "../guest_cpu_reset.h"
#include "imx51_clock_input.h"
#include "imx51_cortex_a8_platform.h"
#include "imx51_dpll1.h"
#include "imx51_dpll2.h"
#include "imx51_dpll3.h"
#include "imx51_id.h"

#include <cstdint>

namespace {

/* MCIMX51RM Table 7-3 CCM memory map. */
constexpr uint32_t kCcr    = 0x00u;
constexpr uint32_t kCsr    = 0x08u;
constexpr uint32_t kCcsr   = 0x0Cu;
constexpr uint32_t kCacrr  = 0x10u;
constexpr uint32_t kCbcdr  = 0x14u;
constexpr uint32_t kCbcmr  = 0x18u;
constexpr uint32_t kCdcdr  = 0x30u;
constexpr uint32_t kChscdr = 0x34u;
constexpr uint32_t kCwdr   = 0x44u;
constexpr uint32_t kCdhipr = 0x48u;
constexpr uint32_t kCdcr   = 0x4Cu;
constexpr uint32_t kCtor   = 0x50u;
constexpr uint32_t kClpcr  = 0x54u;
constexpr uint32_t kCisr   = 0x58u;
constexpr uint32_t kCimr   = 0x5Cu;
constexpr uint32_t kCmeor  = 0x84u;
constexpr uint32_t kCgpr   = 0x64u;
constexpr uint32_t kCcgr0  = 0x68u;
constexpr uint32_t kCcgr2  = 0x70u;
constexpr uint32_t kCcgr6  = 0x80u;

/* Table 7-10 CACRR arm_podf [2:0]; Table 7-24 CDCR arm_freq_shift_divider [2];
   Table 7-30 CGPR arm_async_ref_en [23]. */
constexpr uint32_t kCacrrArmPodfMask       = 0x7u;
constexpr uint32_t kCdcrArmFreqShiftDivider = 1u << 2;
constexpr uint32_t kCgprArmAsyncRefEn      = 1u << 23;

/* Table 9-2 BT_LPB "00 LPBM disabled", BT_LPB_FREQ "111 Normal boot frequency (400 MHz)";
   §54.2.2.2: SBMR "contains bits that reflect the status of Boot Mode Pins", BT_LPB [24:23]. */
constexpr uint64_t kBootRomArmHz = 400000000u;

struct CcmReset { uint32_t off; uint32_t val; };
constexpr CcmReset kResets[] = {
    /* CCR cosc_en [12] set: sync_2 SBOOT nk.exe sub_80051DBC 0x80051FD8 `tst r3, #0x1000`
       records the 24 MHz oscillator rate on it. */
    {0x00, 0x00001EFFu},
    {0x08, 0x00000010u}, {0x14, 0x19239145u}, {0x18, 0x000020C0u},
    {0x1C, 0xA6A2A020u}, {0x20, 0x02A5A88Au}, {0x24, 0x00C30318u},
    {0x28, 0x00860041u}, {0x2C, 0x00860041u}, {0x30, 0x04320DD2u},
    {0x38, 0x02090241u}, {0x3C, 0x00010241u}, {0x40, 0x00010241u},
    {0x4C, 0x00000001u}, {0x54, 0x00000079u}, {0x5C, 0xFFFFFFFFu},
    {0x60, 0x000A0001u}, {0x64, 0x0000FE62u}, {0x68, 0xFFFFFFFFu},
    {0x6C, 0xFFFFFFFFu}, {0x70, 0xFFFFFFFFu}, {0x74, 0xFFFFFFFFu},
    {0x78, 0xFFFFFFFFu}, {0x7C, 0xFFFFFFFFu}, {0x80, 0xFFFFFFFFu},
    {0x84, 0xFFFFFFFFu},
};

/* Table 7-9 CCSR, Table 7-11 CBCDR, Table 7-12 CBCMR, Table 7-24 CDCR. */
constexpr uint32_t kCcsrPll3SwSel  = 1u << 0;
constexpr uint32_t kCcsrPll2SwSel  = 1u << 1;
constexpr uint32_t kCcsrPll1SwSel  = 1u << 2;
constexpr uint32_t kCcsrLpApm      = 1u << 9;
constexpr uint32_t kCbcdrPeriphSel = 1u << 25;
constexpr uint32_t kCbcmrPerIpg    = 1u << 0;
constexpr uint32_t kCbcmrPerLpApm  = 1u << 1;
constexpr uint32_t kCdcrSwDvfsReq  = 1u << 6;
constexpr uint32_t kCdcrSwDvfsEn   = 1u << 5;

/* Figure 7-35 CMEOR: every bit resets to 1, bits 31-24, 11 and 1 are read-only; Table 7-40:
   1 = "override module enable signal". */
constexpr uint32_t kCmeorOverrides = 0x00FFF7FDu;

}

bool Imx51Ccm::ShouldRegister() {
    auto* bd = emu_.TryGet<BoardContext>();
    return bd && bd->GetSocId() == SocId::Imx51;
}

void Imx51Ccm::OnReady() {
    input_    = &emu_.Get<Imx51ClockInput>();
    platform_ = &emu_.Get<Imx51CortexA8Platform>();
    ResetRegisters();
    auto& reset = emu_.Get<GuestCpuReset>();
    reset.RegisterResetListener([this](ResetLineKind) { ResetRegisters(); });
    reset.RegisterResetReleaseListener([this] {
        ApplyRates();
        NotifyGates();
    });
    emu_.Get<PeripheralDispatcher>().Register(this);
    ApplyRates();
}

/* MCIMX51RM Table 54-10: every reset type asserts system_early_rst_b, which resets
   the CCM. */
void Imx51Ccm::ResetRegisters() {
    regs_.fill(0u);
    for (const auto& r : kResets) regs_[r.off >> 2] = r.val;
}

/* Table 7-3: the CCM registers run from CCR at +0x00 to CMEOR at +0x84; +0x34 is CHSCDR per
   the Linux i.MX5 CCM register map, MXC_CCM_CHSCDR. */
static bool IsCcmRegister(uint32_t off) {
    return (off & 0x3u) == 0u && off <= kCmeor;
}

uint32_t Imx51Ccm::ReadWord(uint32_t addr) {
    const uint32_t off = addr - MmioBase();
    if (!IsCcmRegister(off)) HaltUnsupportedAccess("ReadWord", addr, 0);
    if (off == kCisr) {
        emu_.Get<Fatal>().Die("Imx51Ccm: CISR read; the lock and divider-load status events "
                              "are not modeled");
    }
    return regs_[off >> 2];
}

/* Table 7-3: CSR and CDHIPR are read-only, CISR is write-1-to-clear. */
void Imx51Ccm::WriteWord(uint32_t addr, uint32_t value) {
    const uint32_t off = addr - MmioBase();
    if (!IsCcmRegister(off)) HaltUnsupportedAccess("WriteWord", addr, value);
    if (off == kCsr || off == kCdhipr) return;
    if (off == kCisr) {
        regs_[off >> 2] &= ~value;
        return;
    }
    if (off == kCmeor) {
        if ((value & kCmeorOverrides) != kCmeorOverrides) {
            emu_.Get<Fatal>().Die("Imx51Ccm: CMEOR 0x%08X clears a module enable override; "
                                  "the module clock enable gating is not modeled", value);
        }
        return;
    }
    if (off == kCcr || off == kCdcdr || off == kChscdr || off == kCwdr || off == kCtor ||
        off == kCimr) {
        emu_.Get<Fatal>().Die("Imx51Ccm: write 0x%08X to +0x%02X; the effect of this "
                              "register is not modeled", value, off);
    }
    const uint32_t old = regs_[off >> 2];
    if (off == kCacrr && ((old ^ value) & kCacrrArmPodfMask) != 0u &&
        (Reg(kCdcr) & kCdcrArmFreqShiftDivider) != 0u) {
        emu_.Get<Fatal>().Die("Imx51Ccm: CACRR 0x%08X changes arm_podf with CDCR 0x%08X "
                              "arm_freq_shift_divider set; the arm_clk_switch_req hold is "
                              "not modeled", value, Reg(kCdcr));
    }
    regs_[off >> 2] = value;
    const bool timing = off == kCcsr || off == kCacrr || off == kCbcdr || off == kCbcmr ||
                        off == kCdcr || off == kClpcr || off == kCgpr || off == kCcgr2;
    if (timing && old != value) ApplyRates();
    if (off >= kCcgr0 && off <= kCcgr6 && old != value) NotifyGates();
}

void Imx51Ccm::SaveState(StateWriter& w) { w.WriteBytes("regs", regs_.data(), sizeof(regs_)); }

void Imx51Ccm::RestoreState(StateReader& r) { r.ReadBytes("regs", regs_.data(), sizeof(regs_)); }

void Imx51Ccm::PostRestore() {
    ApplyRates();
    NotifyGates();
}

void Imx51Ccm::RegisterRateListener(std::function<void()> fn) {
    listeners_.push_back(std::move(fn));
}

void Imx51Ccm::RegisterGateListener(std::function<void()> fn) {
    gate_listeners_.push_back(std::move(fn));
}

void Imx51Ccm::NotifyGates() {
    for (auto& fn : gate_listeners_) fn();
}

void Imx51Ccm::ApplyRates() {
    auto& clock = emu_.Get<GuestCycleClock>();
    clock.SetClockHz(ArmClkHz());
    const uint64_t hz = clock.CpuHz();
    if (hz != applied_hz_) {
        LOG(SocClkpwr, "Imx51Ccm: ARM clock %llu -> %llu Hz (CCSR %08X CACRR %08X DPLL1 %s)\n",
            static_cast<unsigned long long>(applied_hz_), static_cast<unsigned long long>(hz),
            Reg(kCcsr), Reg(kCacrr),
            emu_.Get<Imx51Dpll1>().OutputKnown() ? "restarted" : "boot ROM state");
        applied_hz_ = hz;
    }
    for (auto& fn : listeners_) fn();
}

/* Figure 7-39: ARM_CLK_ROOT is pll1_sw_clk through the arm_podf divider, value + 1.
   Table 7-30: arm_async_ref_en moves ARM_CLK_ROOT to the async reference circuit. */
uint64_t Imx51Ccm::ArmClkHz() const {
    if ((Reg(kCgpr) & kCgprArmAsyncRefEn) != 0u) {
        emu_.Get<Fatal>().Die("Imx51Ccm: CGPR 0x%08X enables the ARM async reference circuit",
                              Reg(kCgpr));
    }
    const uint32_t podf = Reg(kCacrr) & kCacrrArmPodfMask;
    if ((Reg(kCcsr) & kCcsrPll1SwSel) == 0u && !emu_.Get<Imx51Dpll1>().OutputKnown()) {
        if (podf != 0u) {
            emu_.Get<Fatal>().Die("Imx51Ccm: CACRR arm_podf %u before the first DPLL1 "
                                  "restart; the boot ROM divider is not modeled", podf);
        }
        return kBootRomArmHz;
    }
    return DividedHz(Pll1SwClkHz(), podf + 1u, "ARM_CLK_ROOT");
}

uint64_t Imx51Ccm::DividedHz(uint64_t hz, uint64_t divider, const char* clock) const {
    if (hz % divider != 0u) {
        emu_.Get<Fatal>().Die("Imx51Ccm: %s = %llu Hz / %llu is not a whole number of Hz", clock,
                              static_cast<unsigned long long>(hz),
                              static_cast<unsigned long long>(divider));
    }
    return hz / divider;
}

/* Table 7-9 lp_apm [9]: 0 on-chip oscillator clock output, 1 FPM clock output. */
uint64_t Imx51Ccm::LpApmHz() const {
    if ((Reg(kCcsr) & kCcsrLpApm) != 0u) {
        emu_.Get<Fatal>().Die("Imx51Ccm: CCSR 0x%08X selects the FPM as lp_apm", Reg(kCcsr));
    }
    return input_->OscHz();
}

/* Table 7-9 step_sel [8:7]: 00 lp_apm, 01 pll1 bypass clock, 10 pll2 divided by
   pll2_div_podf [6:5] + 1, 11 pll3 divided by pll3_div_podf [4:3] + 1. */
uint64_t Imx51Ccm::StepClkHz() const {
    const uint32_t ccsr = Reg(kCcsr);
    switch ((ccsr >> 7) & 0x3u) {
        case 0u: return LpApmHz();
        case 2u:
            return DividedHz(emu_.Get<Imx51Dpll2>().OutputHz(), ((ccsr >> 5) & 0x3u) + 1u,
                             "step_clk");
        case 3u:
            return DividedHz(emu_.Get<Imx51Dpll3>().OutputHz(), ((ccsr >> 3) & 0x3u) + 1u,
                             "step_clk");
        default: break;
    }
    emu_.Get<Fatal>().Die("Imx51Ccm: CCSR 0x%08X selects the pll1 bypass clock as step_clk",
                          ccsr);
}

/* Table 7-9 pll1_sw_clk_sel [2]: 0 pll1_main_clk, 1 step_clk. */
uint64_t Imx51Ccm::Pll1SwClkHz() const {
    if ((Reg(kCcsr) & kCcsrPll1SwSel) != 0u) return StepClkHz();
    return emu_.Get<Imx51Dpll1>().OutputHz();
}

/* Table 7-9 pll2_sw_clk_sel [1] / pll3_sw_clk_sel [0]: 1 selects the bypass clock. */
uint64_t Imx51Ccm::Pll2SwClkHz() const {
    if ((Reg(kCcsr) & kCcsrPll2SwSel) != 0u) {
        emu_.Get<Fatal>().Die("Imx51Ccm: CCSR 0x%08X selects the pll2 bypass clock",
                              Reg(kCcsr));
    }
    return emu_.Get<Imx51Dpll2>().OutputHz();
}

uint64_t Imx51Ccm::Pll3SwClkHz() const {
    if ((Reg(kCcsr) & kCcsrPll3SwSel) != 0u) {
        emu_.Get<Fatal>().Die("Imx51Ccm: CCSR 0x%08X selects the pll3 bypass clock",
                              Reg(kCcsr));
    }
    return emu_.Get<Imx51Dpll3>().OutputHz();
}

/* Table 7-12 periph_apm_sel [13:12]: 00 pll1_sw_clk, 01 pll3_sw_clk, 10 lp_apm. */
uint64_t Imx51Ccm::PeriphApmClkHz() const {
    switch ((Reg(kCbcmr) >> 12) & 0x3u) {
        case 0u: return Pll1SwClkHz();
        case 1u: return Pll3SwClkHz();
        case 2u: return LpApmHz();
        default: break;
    }
    emu_.Get<Fatal>().Die("Imx51Ccm: CBCMR 0x%08X selects the reserved periph_apm source",
                          Reg(kCbcmr));
}

/* Table 7-11 periph_clk_sel [25]: 0 pll2_sw_clk, 1 periph_apm_clk. Table 7-24:
   software_DVFS_en with sw_periph_clk_div_req divides by periph_clk_DVFS_podf. */
uint64_t Imx51Ccm::MainBusClkHz() const {
    const uint32_t cdcr = Reg(kCdcr);
    if ((cdcr & kCdcrSwDvfsEn) != 0u && (cdcr & kCdcrSwDvfsReq) != 0u) {
        emu_.Get<Fatal>().Die("Imx51Ccm: CDCR 0x%08X requests the software DVFS periph "
                              "divider", cdcr);
    }
    if ((Reg(kCbcdr) & kCbcdrPeriphSel) != 0u) return PeriphApmClkHz();
    return Pll2SwClkHz();
}

/* Table 7-11: ahb_podf [12:10] and ipg_podf [9:8], each value + 1. */
uint64_t Imx51Ccm::IpgClkHz() const {
    const uint32_t cbcdr = Reg(kCbcdr);
    return DividedHz(DividedHz(MainBusClkHz(), ((cbcdr >> 10) & 0x7u) + 1u, "AHB_CLK_ROOT"),
                     ((cbcdr >> 8) & 0x3u) + 1u, "IPG_CLK_ROOT");
}

/* Table 7-12 perclk_ipg_sel [0] and perclk_lp_apm_sel [1]; Table 7-11
   perclk_pred1 [7:6], perclk_pred2 [5:3], perclk_podf [2:0], each value + 1. */
uint64_t Imx51Ccm::PerclkRootHz() const {
    const uint32_t cbcmr = Reg(kCbcmr);
    if ((cbcmr & kCbcmrPerIpg) != 0u) return IpgClkHz();
    const uint64_t src = (cbcmr & kCbcmrPerLpApm) != 0u ? LpApmHz() : MainBusClkHz();
    const uint32_t cbcdr = Reg(kCbcdr);
    const uint64_t pred1 = DividedHz(src, ((cbcdr >> 6) & 0x3u) + 1u, "perclk_pred1");
    const uint64_t pred2 = DividedHz(pred1, ((cbcdr >> 3) & 0x7u) + 1u, "perclk_pred2");
    return DividedHz(pred2, (cbcdr & 0x7u) + 1u, "PERCLK_ROOT");
}

/* Table 7-3: CCGR0..CCGR6 at 0x68..0x80; Table 7-32: two CG bits per clock. */
uint32_t Imx51Ccm::ClockGate(uint32_t ccgr, uint32_t index) const {
    return (Reg(kCcgr0 + 4u * ccgr) >> (2u * index)) & 0x3u;
}

/* Table 7-32 CG value 01: on in run mode, off in WAIT and STOP; 11: on in all
   modes except STOP; 10: reserved. */
bool Imx51Ccm::ClockRunsIn(uint32_t ccgr, uint32_t index, FreescaleLowPowerMode mode) const {
    const uint32_t cg = ClockGate(ccgr, index);
    if (cg == 2u) {
        emu_.Get<Fatal>().Die("Imx51Ccm: CCGR%u CG%u holds the reserved value 10", ccgr, index);
    }
    switch (mode) {
        case FreescaleLowPowerMode::kRun:  return cg != 0u;
        case FreescaleLowPowerMode::kWait: return cg == 3u;
        default:                           return false;
    }
}

/* Table 7-3: CLPCR at 0x54. 7.4.8.2.1 steps 7-9: the CCM leaves run mode only on
   ARM_DSM_REQUEST, which 14.4.3.4 LPC DSM blocks. */
uint32_t Imx51Ccm::WfiLowPowerMode() const {
    return platform_->DeepSleepRequestEnabled() ? (Reg(kClpcr) & 0x3u) : 0u;
}

REGISTER_SERVICE(Imx51Ccm);
