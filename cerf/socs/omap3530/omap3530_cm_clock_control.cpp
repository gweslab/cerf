#include "omap3530_cm_clock_control.h"

#include "../../core/fatal.h"
#include "../guest_cpu_reset.h"
#include "omap3530_board_clock_setup.h"
#include "omap3530_dpll.h"

namespace {

constexpr uint32_t kOffClkenPll    = 0x00u;
constexpr uint32_t kOffIdlestCkgen = 0x20u;
constexpr uint32_t kOffClksel2Pll  = 0x44u;

/* SPRUF98Y Table 4-178 (printed p. 466-467): CM_CLKEN_PLL [31:16] are the DPLL4
   fields - PWRDN_DSS1 [29], EN_PERIPH_DPLL_LPMODE [26], RESERVED [25:24] "Read
   returns 0", PERIPH_DPLL_FREQSEL [23:20], EN_PERIPH_DPLL [18:16], 0x7 lock. */
constexpr uint32_t kDpll4Fields    = 0xFFFF0000u;
constexpr uint32_t kDpll4Reserved  = 0x03000000u;
constexpr uint32_t kPwrdnDss1      = 1u << 29;
constexpr uint32_t kLpMode         = 1u << 26;
constexpr uint32_t kFreqSelShift   = 20;
constexpr uint32_t kFreqSelMask    = 0xFu << kFreqSelShift;
constexpr uint32_t kEnShift        = 16;
constexpr uint32_t kEnMask         = 0x7u << kEnShift;
constexpr uint32_t kDpll4RateBits  = kPwrdnDss1 | kLpMode | kFreqSelMask | kEnMask;

/* Table 4-192 (printed p. 475): PERIPH_DPLL_MULT [18:8], PERIPH_DPLL_DIV [6:0];
   [31:19] and [7] read 0. */
constexpr uint32_t kClksel2Mask = 0x0007FF7Fu;

}

void Omap3530CmClockControl::OnReady() {
    osc_hz_ = emu_.Get<Omap3530BoardClockSetup>().OscSysClkHz();
    Omap3530PrcmStubBlock::OnReady();
    {
        std::lock_guard<std::mutex> lk(mu_);
        SeedBootDpll4Locked();
    }
    auto& reset = emu_.Get<GuestCpuReset>();
    reset.RegisterResetListener([this](ResetLineKind) {
        std::lock_guard<std::mutex> lk(mu_);
        SeedBootDpll4Locked();
    });
    reset.RegisterResetReleaseListener([this] {
        if (emu_.Get<GuestCpuReset>().DeliveredResetWasResume()) {
            emu_.Get<Fatal>().Die("omap3530 CM_CLOCK_CONTROL: a resume reset; the DPLL4 "
                                  "state across sleep is not modelled");
        }
    });
}

const char* Omap3530CmClockControl::RegisterName(uint32_t off) const {
    switch (off) {
    case 0x00: return "CM_CLKEN_PLL";
    case 0x04: return "CM_CLKEN2_PLL";
    case 0x20: return "CM_IDLEST_CKGEN";
    case 0x24: return "CM_IDLEST2_CKGEN";
    case 0x30: return "CM_AUTOIDLE_PLL";
    case 0x34: return "CM_AUTOIDLE2_PLL";
    case 0x40: return "CM_CLKSEL1_PLL";
    case 0x44: return "CM_CLKSEL2_PLL";
    case 0x48: return "CM_CLKSEL3_PLL";
    case 0x4C: return "CM_CLKSEL4_PLL";
    case 0x50: return "CM_CLKSEL5_PLL";
    case 0x70: return "CM_CLKOUT_CTRL";
    }
    return nullptr;
}

void Omap3530CmClockControl::SeedBootDpll4Locked() {
    const Omap3530PeriphDpllSetting boot =
        emu_.Get<Omap3530BoardClockSetup>().BootPeriphDpll();
    regs_[kOffClkenPll / 4u] = (regs_[kOffClkenPll / 4u] & ~kDpll4Fields) |
                               (boot.clken_pll & kDpll4Fields & ~kDpll4Reserved);
    regs_[kOffClksel2Pll / 4u] = boot.clksel2_pll & kClksel2Mask;
}

/* SPRUF98Y Figure 4-40 (printed p. 310): the DPLL4 reference is SYS_CLK and M4 feeds
   DSS1_ALWON_FCLK. */
bool Omap3530CmClockControl::DeriveDpll4Locked(GuestCycleClock::Rate& rate,
                                               const char*& why) const {
    const uint32_t clken = regs_[kOffClkenPll / 4u];
    if (clken & kLpMode) {
        why = "EN_PERIPH_DPLL_LPMODE selects the LP mode";
        return false;
    }
    why = Omap3530DpllClkoutX2(osc_hz_, (clken & kEnMask) >> kEnShift,
                               (clken & kFreqSelMask) >> kFreqSelShift,
                               regs_[kOffClksel2Pll / 4u], rate.num, rate.den);
    return why == nullptr;
}

GuestCycleClock::Rate Omap3530CmClockControl::Dpll4M4X2Input() const {
    std::lock_guard<std::mutex> lk(mu_);
    GuestCycleClock::Rate rate;
    const char* why = nullptr;
    if (!DeriveDpll4Locked(rate, why)) {
        emu_.Get<Fatal>().Die("omap3530 CM_CLOCK_CONTROL: DPLL4 %s (CLKEN 0x%08X CLKSEL2 "
                              "0x%08X); that DSS1_ALWON_FCLK source is not modelled", why,
                              regs_[kOffClkenPll / 4u], regs_[kOffClksel2Pll / 4u]);
    }
    if (regs_[kOffClkenPll / 4u] & kPwrdnDss1) {
        emu_.Get<Fatal>().Die("omap3530 CM_CLOCK_CONTROL: PWRDN_DSS1 powers down the DPLL4 "
                              "M4X2 path (CLKEN 0x%08X); a stopped DSS1_ALWON_FCLK is not "
                              "modelled", regs_[kOffClkenPll / 4u]);
    }
    LOG(Periph, "[CM_CLKCTRL] DPLL4 CLKOUTX2 %llu/%llu Hz (CLKEN 0x%08X CLKSEL2 0x%08X)\n",
        static_cast<unsigned long long>(rate.num), static_cast<unsigned long long>(rate.den),
        regs_[kOffClkenPll / 4u], regs_[kOffClksel2Pll / 4u]);
    return rate;
}

/* Table 4-182 (printed p. 469-470): CM_IDLEST_CKGEN reports ST_PERIPH_CLK [1] DPLL4
   locked and ST_DSS1_CLK [11] DSS1_ALWON_FCLK active next to ST_CORE_CLK [0] DPLL3
   and the activity of the other DPLL3/DPLL4 output clocks. */
uint32_t Omap3530CmClockControl::ReadWord(uint32_t addr) {
    if (addr - MmioBase() == kOffIdlestCkgen) {
        emu_.Get<Fatal>().Die("omap3530 CM_CLOCK_CONTROL: CM_IDLEST_CKGEN read; the clock "
                              "activity status it reports is not modelled");
    }
    return Omap3530PrcmStubBlock::ReadWord(addr);
}

uint16_t Omap3530CmClockControl::ReadHalf(uint32_t addr) {
    if (((addr - MmioBase()) & ~3u) == kOffIdlestCkgen) {
        HaltUnsupportedAccess("ReadHalf(CM_IDLEST_CKGEN)", addr, 0);
    }
    return Omap3530PrcmStubBlock::ReadHalf(addr);
}

void Omap3530CmClockControl::WriteWord(uint32_t addr, uint32_t value) {
    const uint32_t off = addr - MmioBase();
    if (off != kOffClkenPll && off != kOffClksel2Pll) {
        Omap3530PrcmStubBlock::WriteWord(addr, value);
        return;
    }
    const uint32_t next = off == kOffClkenPll ? (value & ~kDpll4Reserved) : (value & kClksel2Mask);
    const uint32_t rate = off == kOffClkenPll ? kDpll4RateBits : kClksel2Mask;
    std::lock_guard<std::mutex> lk(mu_);
    const uint32_t prev = regs_[off / 4u];
    if (((prev ^ next) & rate) != 0u) {
        emu_.Get<Fatal>().Die(
            "omap3530 CM_CLOCK_CONTROL: write 0x%08X to +0x%02X (was 0x%08X) changes the "
            "DPLL4 mode, FREQSEL, LP mode, M4X2 power or M/N; DPLL4 relock, bypass and "
            "power-down are not modelled", value, off, prev);
    }
    regs_[off / 4u] = next;
}

void Omap3530CmClockControl::WriteHalf(uint32_t addr, uint16_t value) {
    const uint32_t off = (addr - MmioBase()) & ~3u;
    if (off == kOffClkenPll || off == kOffClksel2Pll) {
        HaltUnsupportedAccess("WriteHalf(DPLL4 control register)", addr, value);
    }
    Omap3530PrcmStubBlock::WriteHalf(addr, value);
}

REGISTER_SERVICE(Omap3530CmClockControl);
