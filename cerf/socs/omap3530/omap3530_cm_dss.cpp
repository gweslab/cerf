#include "omap3530_cm_dss.h"

#include "../../core/fatal.h"
#include "../guest_cpu_reset.h"

namespace {

constexpr uint32_t kOffFclken = 0x00u;
constexpr uint32_t kOffClksel = 0x40u;

/* SPRUF98Y Table 4-203 (printed p. 479): CM_FCLKEN_DSS EN_TV [2], EN_DSS2 [1],
   EN_DSS1 [0], [31:3] read 0, reset 0x0. */
constexpr uint32_t kFclkenMask = 0x7u;
constexpr uint32_t kEnDss1     = 1u << 0;

/* Table 4-211 (printed p. 481-482): CM_CLKSEL_DSS CLKSEL_TV [12:8] and CLKSEL_DSS1
   [4:0], divide by 1 to 16, "Other enums: Reserved", each reset 0x10. */
constexpr uint32_t kClkselMask  = 0x00001F1Fu;
constexpr uint32_t kClkselReset = 0x00001010u;

bool ClkselDividerValid(uint32_t d) { return d >= 1u && d <= 16u; }

}

void Omap3530CmDss::OnReady() {
    clock_control_ = &emu_.Get<Omap3530CmClockControl>();
    Omap3530PrcmStubBlock::OnReady();
    {
        std::lock_guard<std::mutex> lk(mu_);
        ApplyResetsLocked();
    }
    emu_.Get<GuestCpuReset>().RegisterResetListener([this](ResetLineKind) {
        std::lock_guard<std::mutex> lk(mu_);
        ApplyResetsLocked();
    });
}

const char* Omap3530CmDss::RegisterName(uint32_t off) const {
    switch (off) {
    case 0x00: return "CM_FCLKEN_DSS";
    case 0x10: return "CM_ICLKEN_DSS";
    case 0x20: return "CM_IDLEST_DSS";
    case 0x30: return "CM_AUTOIDLE_DSS";
    case 0x40: return "CM_CLKSEL_DSS";
    case 0x44: return "CM_SLEEPDEP_DSS";
    case 0x48: return "CM_CLKSTCTRL_DSS";
    case 0x4C: return "CM_CLKSTST_DSS";
    }
    return nullptr;
}

/* Table 4-202 (printed p. 478): both registers have reset type W; Table 4-7
   note (printed p. 259): "C = Cold reset, W = Warm reset". */
void Omap3530CmDss::ApplyResetsLocked() {
    regs_[kOffFclken / 4u] = 0u;
    regs_[kOffClksel / 4u] = kClkselReset;
}

void Omap3530CmDss::RegisterDss1Listener(std::function<void()> fn) {
    dss1_listeners_.push_back(std::move(fn));
}

bool Omap3530CmDss::Dss1FclkEnabled() const {
    std::lock_guard<std::mutex> lk(mu_);
    return (regs_[kOffFclken / 4u] & kEnDss1) != 0u;
}

GuestCycleClock::Rate Omap3530CmDss::Dss1AlwonFclk() const {
    uint32_t m4;
    {
        std::lock_guard<std::mutex> lk(mu_);
        m4 = regs_[kOffClksel / 4u] & 0x1Fu;
    }
    GuestCycleClock::Rate rate = clock_control_->Dpll4M4X2Input();
    rate.den *= m4;
    return rate;
}

void Omap3530CmDss::WriteWord(uint32_t addr, uint32_t value) {
    const uint32_t off = addr - MmioBase();
    if (off != kOffFclken && off != kOffClksel) {
        Omap3530PrcmStubBlock::WriteWord(addr, value);
        return;
    }
    bool dss1_changed;
    {
        std::lock_guard<std::mutex> lk(mu_);
        const uint32_t prev = regs_[off / 4u];
        if (off == kOffFclken) {
            const uint32_t next = value & kFclkenMask;
            regs_[off / 4u] = next;
            dss1_changed = ((prev ^ next) & kEnDss1) != 0u;
        } else {
            const uint32_t next = value & kClkselMask;
            if (!ClkselDividerValid(next & 0x1Fu) || !ClkselDividerValid(next >> 8)) {
                emu_.Get<Fatal>().Die("omap3530 CM_DSS: CM_CLKSEL_DSS write 0x%08X selects a "
                                      "reserved DPLL4 M3 or M4 divider", value);
            }
            regs_[off / 4u] = next;
            dss1_changed = ((prev ^ next) & 0x1Fu) != 0u;
        }
    }
    if (dss1_changed) {
        for (auto& fn : dss1_listeners_) fn();
    }
}

void Omap3530CmDss::WriteHalf(uint32_t addr, uint16_t value) {
    const uint32_t off = (addr - MmioBase()) & ~3u;
    if (off == kOffFclken || off == kOffClksel) {
        HaltUnsupportedAccess("WriteHalf(DSS clock register)", addr, value);
    }
    Omap3530PrcmStubBlock::WriteHalf(addr, value);
}

REGISTER_SERVICE(Omap3530CmDss);
