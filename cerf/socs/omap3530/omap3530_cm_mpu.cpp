#include "omap3530_cm_mpu.h"

#include "../../core/fatal.h"
#include "../../jit/guest_cycle_clock.h"
#include "../guest_cpu_reset.h"
#include "omap3530_board_clock_setup.h"
#include "omap3530_dpll.h"

namespace {

constexpr uint32_t kOffClkenPll   = 0x04u;
constexpr uint32_t kOffIdlestPll  = 0x24u;
constexpr uint32_t kOffClksel1Pll = 0x40u;
constexpr uint32_t kOffClksel2Pll = 0x44u;

/* SPRUF98Y Table 4-112 (printed p. 437-438): CM_CLKEN_PLL_MPU [31:11] R, [9:8]
   RESERVED "Read returns 0"; EN_MPU_DPLL_LPMODE [10], MPU_DPLL_FREQSEL [7:4],
   EN_MPU_DPLL_DRIFTGUARD [3], EN_MPU_DPLL [2:0] RW. */
constexpr uint32_t kClkenMask    = 0x000004FFu;
constexpr uint32_t kEnMask       = 0x7u;
constexpr uint32_t kEnLock       = 0x7u;
constexpr uint32_t kFreqSelShift = 4;
constexpr uint32_t kFreqSelMask  = 0xFu << kFreqSelShift;

/* Table 4-120 (printed p. 440): MPU_CLK_SRC [21:19], MPU_DPLL_MULT [18:8],
   MPU_DPLL_DIV [6:0]. */
constexpr uint32_t kClksel1Mask     = 0x003FFF7Fu;
constexpr uint32_t kClksel1MultDiv  = 0x0007FF7Fu;

/* Table 4-122 (printed p. 441): MPU_DPLL_CLKOUT_DIV [4:0]. */
constexpr uint32_t kClksel2Mask  = 0x0000001Fu;

bool DpllOffset(uint32_t off) {
    return off == kOffClkenPll || off == kOffClksel1Pll || off == kOffClksel2Pll;
}

}

void Omap3530CmMpu::OnReady() {
    osc_hz_ = emu_.Get<Omap3530BoardClockSetup>().OscSysClkHz();
    Omap3530PrcmStubBlock::OnReady();
    {
        std::lock_guard<std::mutex> lk(mu_);
        SeedBootDpllLocked();
    }
    auto& reset = emu_.Get<GuestCpuReset>();
    reset.RegisterResetListener([this](ResetLineKind) {
        std::lock_guard<std::mutex> lk(mu_);
        SeedBootDpllLocked();
    });
    reset.RegisterResetReleaseListener([this] {
        if (emu_.Get<GuestCpuReset>().DeliveredResetWasResume()) {
            emu_.Get<Fatal>().Die("omap3530 CM_MPU: a resume reset; the DPLL1 state "
                                  "across sleep is not modelled");
        }
        ApplyRate();
    });
}

const char* Omap3530CmMpu::RegisterName(uint32_t off) const {
    switch (off) {
    case 0x04: return "CM_CLKEN_PLL_MPU";
    case 0x20: return "CM_IDLEST_MPU";
    case 0x24: return "CM_IDLEST_PLL_MPU";
    case 0x34: return "CM_AUTOIDLE_PLL_MPU";
    case 0x40: return "CM_CLKSEL1_PLL_MPU";
    case 0x44: return "CM_CLKSEL2_PLL_MPU";
    case 0x48: return "CM_CLKSTCTRL_MPU";
    case 0x4C: return "CM_CLKSTST_MPU";
    }
    return nullptr;
}

void Omap3530CmMpu::SeedBootDpllLocked() {
    const Omap3530MpuDpllSetting boot = emu_.Get<Omap3530BoardClockSetup>().BootMpuDpll();
    regs_[kOffClkenPll / 4u]   = boot.clken_pll & kClkenMask;
    regs_[kOffClksel1Pll / 4u] = boot.clksel1_pll & kClksel1Mask;
    regs_[kOffClksel2Pll / 4u] = boot.clksel2_pll & kClksel2Mask;
}

/* SPRUF98Y Table 4-56 (printed p. 352): locked MPU_CLK = SYS_CLK * M * 2 /
   ((N + 1) * M2). §3.2.1.1 (printed p. 220): ARM_FCLK runs at one half the
   MPU_CLK when DPLL1 is locked. */
bool Omap3530CmMpu::DeriveArmFclkLocked(uint64_t& hz, const char*& why) const {
    const uint32_t clken   = regs_[kOffClkenPll / 4u];
    const uint32_t clksel1 = regs_[kOffClksel1Pll / 4u];
    const uint32_t clksel2 = regs_[kOffClksel2Pll / 4u];
    const uint64_t m2  = clksel2 & 0x1Fu;
    const uint32_t src = (clksel1 >> 19) & 0x7u;
    if (m2 == 0u || m2 > 16u) {
        why = "MPU_DPLL_CLKOUT_DIV is reserved";
        return false;
    }
    if (src != 1u && src != 2u && src != 4u) {
        why = "MPU_CLK_SRC is reserved";
        return false;
    }
    uint64_t num = 0;
    uint64_t den = 0;
    why = Omap3530DpllClkoutX2(osc_hz_, clken & kEnMask, (clken & kFreqSelMask) >> kFreqSelShift,
                               clksel1, num, den);
    if (why) return false;
    den *= m2;
    if (num % den != 0u || (num / den) % 2u != 0u) {
        why = "ARM_FCLK is not a whole number of Hz";
        return false;
    }
    hz = num / den / 2u;
    return true;
}

uint64_t Omap3530CmMpu::ArmFclkHz() const {
    std::lock_guard<std::mutex> lk(mu_);
    uint64_t    hz  = 0;
    const char* why = nullptr;
    if (!DeriveArmFclkLocked(hz, why)) {
        emu_.Get<Fatal>().Die(
            "omap3530 CM_MPU: DPLL1 %s (CLKEN 0x%08X CLKSEL1 0x%08X CLKSEL2 0x%08X); "
            "that MPU clock is not modelled", why, regs_[kOffClkenPll / 4u],
            regs_[kOffClksel1Pll / 4u], regs_[kOffClksel2Pll / 4u]);
    }
    LOG(Periph, "[CM_MPU] DPLL1 ARM_FCLK %llu Hz (CLKEN 0x%08X CLKSEL1 0x%08X "
                "CLKSEL2 0x%08X)\n", static_cast<unsigned long long>(hz),
        regs_[kOffClkenPll / 4u], regs_[kOffClksel1Pll / 4u],
        regs_[kOffClksel2Pll / 4u]);
    return hz;
}

void Omap3530CmMpu::ApplyRate() {
    emu_.Get<GuestCycleClock>().SetClockHz(ArmFclkHz());
}

/* Table 4-116 (printed p. 439): CM_IDLEST_PLL_MPU ST_MPU_CLK [0], "0x0: DPLL1
   is bypassed", "0x1: DPLL1 is locked"; bits [31:1] read 0. */
uint32_t Omap3530CmMpu::ReadWord(uint32_t addr) {
    if (addr - MmioBase() == kOffIdlestPll) {
        std::lock_guard<std::mutex> lk(mu_);
        return (regs_[kOffClkenPll / 4u] & kEnMask) == kEnLock ? 1u : 0u;
    }
    return Omap3530PrcmStubBlock::ReadWord(addr);
}

uint16_t Omap3530CmMpu::ReadHalf(uint32_t addr) {
    if ((addr - MmioBase()) / 4u == kOffIdlestPll / 4u) {
        HaltUnsupportedAccess("ReadHalf(CM_IDLEST_PLL_MPU)", addr, 0);
    }
    return Omap3530PrcmStubBlock::ReadHalf(addr);
}

void Omap3530CmMpu::WriteWord(uint32_t addr, uint32_t value) {
    const uint32_t off = addr - MmioBase();
    if (off == kOffIdlestPll) {
        HaltUnsupportedAccess("WriteWord(CM_IDLEST_PLL_MPU)", addr, value);
    }
    if (!DpllOffset(off)) {
        Omap3530PrcmStubBlock::WriteWord(addr, value);
        return;
    }
    const uint32_t mask = off == kOffClkenPll   ? kClkenMask
                        : off == kOffClksel1Pll ? kClksel1Mask
                                                : kClksel2Mask;
    const uint32_t rate = off == kOffClkenPll   ? (kEnMask | kFreqSelMask)
                        : off == kOffClksel1Pll ? kClksel1MultDiv
                                                : kClksel2Mask;
    std::lock_guard<std::mutex> lk(mu_);
    const uint32_t prev = regs_[off / 4u];
    const uint32_t next = value & mask;
    if (((prev ^ next) & rate) != 0u) {
        emu_.Get<Fatal>().Die(
            "omap3530 CM_MPU: write 0x%08X to +0x%02X (was 0x%08X) changes the DPLL1 "
            "mode or its M/N/M2/FREQSEL; DPLL1 relock and bypass are not modelled",
            value, off, prev);
    }
    if (off == kOffClksel1Pll) {
        const uint32_t src = (next >> 19) & 0x7u;
        if (src != 1u && src != 2u && src != 4u) {
            emu_.Get<Fatal>().Die("omap3530 CM_MPU: CLKSEL1_PLL_MPU write 0x%08X selects "
                                  "the reserved MPU_CLK_SRC %u", value, src);
        }
    }
    regs_[off / 4u] = next;
}

void Omap3530CmMpu::WriteHalf(uint32_t addr, uint16_t value) {
    const uint32_t off = (addr - MmioBase()) & ~3u;
    if (DpllOffset(off) || off == kOffIdlestPll) {
        HaltUnsupportedAccess("WriteHalf(DPLL1 control register)", addr, value);
    }
    Omap3530PrcmStubBlock::WriteHalf(addr, value);
}

void Omap3530CmMpu::RestoreState(StateReader& r) {
    std::lock_guard<std::mutex> lk(mu_);
    RestoreRegsLocked(r);
    if ((regs_[kOffClkenPll / 4u] & ~kClkenMask) != 0u ||
        (regs_[kOffClksel1Pll / 4u] & ~kClksel1Mask) != 0u ||
        (regs_[kOffClksel2Pll / 4u] & ~kClksel2Mask) != 0u) {
        r.Reject("omap3530 CM_MPU: restored DPLL1 registers set reserved bits");
    }
    uint64_t    hz  = 0;
    const char* why = nullptr;
    if (!DeriveArmFclkLocked(hz, why)) {
        r.Reject("omap3530 CM_MPU: restored DPLL1 %s", why);
    }
}

REGISTER_SERVICE(Omap3530CmMpu);
