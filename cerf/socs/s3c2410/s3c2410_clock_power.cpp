#include "s3c2410_clocks.h"

#include "../../boards/board_context.h"
#include "s3c2410_id.h"
#include "../../core/cerf_emulator.h"
#include "../../core/fatal.h"
#include "../../core/log.h"
#include "../../host/guest_deep_sleep.h"
#include "../../jit/arm/arm_mmu.h"
#include "../../jit/guest_cycle_clock.h"
#include "../../jit/guest_engine.h"
#include "../../peripherals/peripheral_base.h"
#include "../../peripherals/peripheral_dispatcher.h"
#include "../../state/state_stream.h"
#include "../guest_cpu_reset.h"
#include "s3c2410_clock_input.h"

#include <cstdint>
#include <functional>
#include <vector>

namespace {

constexpr uint32_t kOffLockTime = 0x00u;
constexpr uint32_t kOffMpllCon = 0x04u;
constexpr uint32_t kOffUpllCon = 0x08u;
constexpr uint32_t kOffClkCon  = 0x0Cu;
constexpr uint32_t kOffClkSlow = 0x10u;
constexpr uint32_t kOffClkDivn = 0x14u;
constexpr uint32_t kSlotCount  = 6u;

constexpr uint32_t kResetValues[kSlotCount] = {
    0x00FFFFFFu, 0x0005C080u, 0x00028080u, 0x0007FFF0u, 0x00000004u, 0x00000000u,
};

constexpr uint32_t kFastBusMask    = 3u << 30;
constexpr uint32_t kClkConSpecial  = 1u << 0;
constexpr uint32_t kClkConIdle     = 1u << 2;
constexpr uint32_t kClkConPowerOff = 1u << 3;
constexpr uint32_t kClkConPwmTimer = 1u << 8;
constexpr uint32_t kClkConGateMask = 0x0007FFF0u;
constexpr uint32_t kClkSlowSlowBit = 1u << 4;
constexpr uint32_t kClkSlowMpllOff = 1u << 5;
constexpr uint32_t kClkSlowUclkOff = 1u << 7;
constexpr uint32_t kClkSlowValMask = 0x7u;
constexpr uint32_t kClkDivnPdivn   = 1u << 0;
constexpr uint32_t kClkDivnHdivn   = 1u << 1;
constexpr uint32_t kClkDivnHdivn1  = 1u << 2;

class S3C2410ClockPower : public S3C2410Clocks {
public:
    using S3C2410Clocks::S3C2410Clocks;

    bool ShouldRegister() override {
        auto* bd = emu_.TryGet<BoardContext>();
        return bd && bd->GetSocId() == SocId::S3c2410;
    }

    void OnReady() override {
        fin_hz_ = emu_.Get<S3C2410ClockInput>().FinHz();
        if (fin_hz_ == 0u) {
            emu_.Get<Fatal>().Die("S3C2410ClockPower: the board reports a 0 Hz clock input");
        }
        ResetRegisters();
        emu_.Get<ArmMmu>().RegisterControlRegisterListener([this] { ApplyRates(); });
        emu_.Get<GuestCpuReset>().RegisterResetListener([this](ResetLineKind) {
            ResetRegisters();
        });
        emu_.Get<GuestCpuReset>().RegisterResetReleaseListener([this] { ApplyRates(); });
    }

    uint64_t FclkHz()      const override { return fclk_hz_; }
    uint64_t HclkHz()      const override { return hclk_hz_; }
    uint64_t PclkHz()      const override { return pclk_hz_; }

    /* ARM920T TRM DDI 0151C p.2-14 Table 2-11: c1[31:30] iA=0 nF=0 is FastBus.
       S3C2410A UM p.7-8 note 2: with HDIVN=1 and the fast bus mode the CPU
       operates by the HCLK. */
    uint64_t CoreClockHz() const override {
        const uint32_t c1 = emu_.Get<ArmMmu>().State()->control_register.word;
        return (c1 & kFastBusMask) == 0u ? hclk_hz_ : fclk_hz_;
    }

    bool PwmTimerClockOn() const override {
        return (regs_[kOffClkCon / 4u] & kClkConPwmTimer) != 0u;
    }

    void RegisterRateListener(std::function<void()> fn) override {
        listeners_.push_back(std::move(fn));
    }

    uint32_t ReadRegister(uint32_t offset) override {
        const uint32_t slot = Slot(offset);
        if (offset == kOffLockTime || offset == kOffUpllCon) {
            emu_.Get<Fatal>().Die(
                "S3C2410ClockPower: read of +0x%02X, whose effect CERF does not "
                "model - the PLL lock interval gates FCLK and UPLL drives UCLK",
                offset);
        }
        const uint32_t value = regs_[slot];
        LOG(SocClkpwr, "read  +0x%02X -> 0x%08X\n", offset, value);
        return value;
    }

    void WriteRegister(uint32_t offset, uint32_t value) override {
        const uint32_t slot = Slot(offset);
        LOG(SocClkpwr, "write +0x%02X = 0x%08X\n", offset, value);
        regs_[slot] = value;
        switch (offset) {
            case kOffMpllCon:
                pll_configured_ = true;
                ApplyRates();
                return;
            /* S3C2410A UM p.7-22: MPLL_OFF [5] turns the PLL off; UCLK_ON [7] set
               turns UCLK and the UPLL off. */
            case kOffClkSlow:
                if ((value & kClkSlowMpllOff) != 0u) {
                    emu_.Get<Fatal>().Die(
                        "S3C2410ClockPower: CLKSLOW MPLL_OFF turns the MPLL off, "
                        "which CERF does not model");
                }
                if ((value & kClkSlowUclkOff) != 0u) {
                    emu_.Get<Fatal>().Die(
                        "S3C2410ClockPower: CLKSLOW UCLK_ON=1 turns UCLK and the "
                        "UPLL off, which CERF does not model");
                }
                ApplyRates();
                return;
            case kOffClkDivn:
                ApplyRates();
                return;
            /* S3C2410A UM p.7-21: [18:4] gate PCLK or HCLK into the on-chip blocks,
               [2] enters IDLE mode and [0] selects SPECIAL mode. */
            case kOffClkCon: {
                if ((value & (kClkConIdle | kClkConPowerOff)) ==
                    (kClkConIdle | kClkConPowerOff)) {
                    emu_.Get<Fatal>().Die(
                        "S3C2410ClockPower: CLKCON selects IDLE and POWER_OFF "
                        "together, which CERF does not model");
                }
                if ((value & kClkConSpecial) != 0u) {
                    emu_.Get<Fatal>().Die(
                        "S3C2410ClockPower: CLKCON SM_BIT selects SPECIAL mode, "
                        "which CERF does not model");
                }
                const uint32_t gated_off =
                    ~value & kClkConGateMask & ~kClkConPwmTimer;
                if (gated_off != 0u) {
                    emu_.Get<Fatal>().Die(
                        "S3C2410ClockPower: CLKCON clears the clock gates 0x%05X, "
                        "whose effect CERF does not model", gated_off);
                }
                for (auto& fn : listeners_) fn();
                if ((value & kClkConPowerOff) != 0u) {
                    emu_.Get<GuestDeepSleep>().Enter();
                    return;
                }
                /* S3C2410A UM p.7-17: CLKCON[2] set enters IDLE mode; p.7-1: only
                   the core's FCLK stops, every peripheral keeps its clock, and any
                   interrupt request to the CPU wakes it. */
                if ((value & kClkConIdle) != 0u) {
                    emu_.Get<GuestEngine>().EnterIdleWait();
                }
                return;
            }
            default:
                return;
        }
    }

    void SaveState(StateWriter& w) {
        for (uint32_t i = 0; i < kSlotCount; ++i) w.Write<uint32_t>("regs", regs_[i]);
        w.Write<uint8_t>("pll_configured", pll_configured_ ? 1u : 0u);
    }

    void RestoreState(StateReader& r) {
        for (uint32_t i = 0; i < kSlotCount; ++i) r.Read("regs", regs_[i]);
        uint8_t configured = 0;
        r.Read("pll_configured", configured);
        pll_configured_ = configured != 0u;
        Derive();
    }

    void PostRestore() { ApplyRates(); }

private:
    uint32_t Slot(uint32_t offset) {
        if ((offset & 3u) != 0u || offset / 4u >= kSlotCount) {
            emu_.Get<Fatal>().Die("S3C2410ClockPower: unsupported register offset 0x%02X",
                                  offset);
        }
        return offset / 4u;
    }

    void ResetRegisters() {
        for (uint32_t i = 0; i < kSlotCount; ++i) regs_[i] = kResetValues[i];
        pll_configured_ = false;
        Derive();
    }

    void Derive() {
        const uint32_t mpll = regs_[kOffMpllCon / 4u];
        const uint32_t slow = regs_[kOffClkSlow / 4u];
        const uint32_t divn = regs_[kOffClkDivn / 4u];

        if ((slow & kClkSlowSlowBit) != 0u) {
            const uint32_t slow_val = slow & kClkSlowValMask;
            fclk_hz_ = slow_val != 0u ? fin_hz_ / (2u * slow_val) : fin_hz_;
        } else if (pll_configured_) {
            const uint64_t m = ((mpll >> 12) & 0xFFu) + 8u;
            const uint64_t p = ((mpll >> 4) & 0x3Fu) + 2u;
            const uint64_t s = mpll & 0x3u;
            fclk_hz_ = (m * fin_hz_) / (p << s);
        } else {
            fclk_hz_ = fin_hz_;
        }

        if ((divn & kClkDivnHdivn1) != 0u) {
            hclk_hz_ = fclk_hz_ / 4u;
            pclk_hz_ = fclk_hz_ / 4u;
        } else {
            hclk_hz_ = (divn & kClkDivnHdivn) != 0u ? fclk_hz_ / 2u : fclk_hz_;
            pclk_hz_ = (divn & kClkDivnPdivn) != 0u ? hclk_hz_ / 2u : hclk_hz_;
        }
        LOG(SocClkpwr, "S3C2410ClockPower: FCLK %llu HCLK %llu PCLK %llu Hz\n",
            static_cast<unsigned long long>(fclk_hz_),
            static_cast<unsigned long long>(hclk_hz_),
            static_cast<unsigned long long>(pclk_hz_));
    }

    void ApplyRates() {
        Derive();
        emu_.Get<GuestCycleClock>().SetClockHz(CoreClockHz());
        for (auto& fn : listeners_) fn();
    }

    std::vector<std::function<void()>> listeners_;
    uint32_t regs_[kSlotCount] = {};
    uint64_t fin_hz_         = 0;
    uint64_t fclk_hz_        = 0;
    uint64_t hclk_hz_        = 0;
    uint64_t pclk_hz_        = 0;
    bool     pll_configured_ = false;
};

class S3C2410ClockPowerMmio : public Peripheral {
public:
    using Peripheral::Peripheral;

    bool ShouldRegister() override {
        auto* bd = emu_.TryGet<BoardContext>();
        return bd && bd->GetSocId() == SocId::S3c2410;
    }

    void OnReady() override {
        emu_.Get<PeripheralDispatcher>().Register(this);
    }

    uint32_t MmioBase() const override { return 0x4C000000u; }
    uint32_t MmioSize() const override { return 0x00100000u; }

    uint32_t ReadWord(uint32_t addr) override {
        const uint32_t off = addr - MmioBase();
        if (off >= kSlotCount * 4u) HaltUnsupportedAccess("ReadWord", addr, 0);
        return Owner().ReadRegister(off);
    }

    void WriteWord(uint32_t addr, uint32_t value) override {
        const uint32_t off = addr - MmioBase();
        if (off >= kSlotCount * 4u) HaltUnsupportedAccess("WriteWord", addr, value);
        Owner().WriteRegister(off, value);
    }

    void SaveState(StateWriter& w) override    { Owner().SaveState(w); }
    void RestoreState(StateReader& r) override { Owner().RestoreState(r); }
    void PostRestore() override                { Owner().PostRestore(); }

private:
    S3C2410ClockPower& Owner() {
        return static_cast<S3C2410ClockPower&>(emu_.Get<S3C2410Clocks>());
    }
};

}

REGISTER_SERVICE_AS(S3C2410ClockPower, S3C2410Clocks);
REGISTER_SERVICE   (S3C2410ClockPowerMmio);
