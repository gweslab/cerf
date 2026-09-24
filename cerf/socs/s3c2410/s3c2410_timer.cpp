#include "../../peripherals/peripheral_base.h"

#include "../../boards/board_context.h"
#include "s3c2410_id.h"
#include "../../core/cerf_emulator.h"
#include "../../core/fatal.h"
#include "../../core/log.h"
#include "../../core/tick_scale.h"
#include "../../jit/guest_cycle_clock.h"
#include "../../peripherals/peripheral_dispatcher.h"
#include "../../state/state_stream.h"
#include "../guest_cpu_reset.h"
#include "../irq_controller.h"
#include "s3c2410_clocks.h"

#include <cstdint>
#include <numeric>

namespace {

struct TimerBits {
    int start;
    int manual_update;
    int auto_reload;
};
constexpr TimerBits kTcon[5] = {
    { 0,   1,   3  },
    { 8,   9,   11 },
    { 12,  13,  15 },
    { 16,  17,  19 },
    { 20,  21,  22 },
};

constexpr int kIrqTimerN[5] = { 10, 11, 12, 13, 14 };

constexpr uint32_t kCountMask = 0xFFFFu;

class S3C2410Timer : public Peripheral {
public:
    using Peripheral::Peripheral;

    bool ShouldRegister() override {
        auto* bd = emu_.TryGet<BoardContext>();
        return bd && bd->GetSocId() == SocId::S3c2410;
    }
    void OnReady() override {
        clocks_ = &emu_.Get<S3C2410Clocks>();
        clock_  = &emu_.Get<GuestCycleClock>();
        gated_  = !clocks_->PwmTimerClockOn();
        for (int i = 0; i < 5; ++i) {
            event_[i] = clock_->Add([this, i] { OnMatch(i); });
            SetUnits(i);
        }
        clocks_->RegisterRateListener([this] { OnRateChange(); });
        emu_.Get<GuestCpuReset>().RegisterResetListener([this](ResetLineKind) {
            OnResetLine();
        });
        emu_.Get<PeripheralDispatcher>().Register(this);
    }

    uint32_t MmioBase() const override { return 0x51000000u; }
    uint32_t MmioSize() const override { return 0x00100000u; }

    uint32_t ReadWord (uint32_t addr) override;
    void     WriteWord(uint32_t addr, uint32_t value) override;

    void SaveState(StateWriter& w) override;
    void RestoreState(StateReader& r) override;

private:
    enum class RegKind { Tcfg0, Tcfg1, Tcon, TcntbN, TcmpbN, TcntoN, OutOfRange };
    struct DecodedReg { RegKind kind; int timer_idx; };

    static DecodedReg DecodeReg(uint32_t offset);

    struct TimerState {
        uint32_t tcntb         = 0;
        uint32_t tcmpb         = 0;
        bool     running       = false;
        bool     auto_reload   = false;
        uint32_t count         = 0;
        uint64_t origin_cycles = 0;
        uint64_t zero_tick     = 0;
        uint64_t tk_unit       = 1;
        uint64_t cyc_unit      = 1;
    };

    uint64_t Now() const { return clock_->Cycles(); }

    void     SetUnits(int n);
    uint64_t TicksSince(const TimerState& t, uint64_t now) const {
        return ScaleU64(now - t.origin_cycles, t.tk_unit, t.cyc_unit);
    }
    uint32_t CountAt(int n, uint64_t now) const;
    void     SetCount(int n, uint64_t now, uint32_t count);
    void     Reanchor(int n, uint64_t now) { SetCount(n, now, CountAt(n, now)); }
    void     ArmTimer(int n);
    void     ApplyTconWrite(uint32_t new_tcon, uint64_t now);

    void OnMatch(int n);
    void OnRateChange();
    void OnResetLine();

    S3C2410Clocks*          clocks_   = nullptr;
    GuestCycleClock*        clock_    = nullptr;
    GuestCycleClock::Event* event_[5] = {};
    bool                    gated_    = false;
    uint32_t                tcfg0_    = 0;
    uint32_t                tcfg1_    = 0;
    uint32_t                tcon_     = 0;
    TimerState              timers_[5];
};

S3C2410Timer::DecodedReg S3C2410Timer::DecodeReg(uint32_t offset) {
    if (offset == 0x00u) return { RegKind::Tcfg0, 0 };
    if (offset == 0x04u) return { RegKind::Tcfg1, 0 };
    if (offset == 0x08u) return { RegKind::Tcon,  0 };
    /* S3C2410A UM p.10-15: TCNTB0 0x5100000C, TCMPB0 0x51000010,
       TCNTO0 0x51000014; timers 1..3 repeat the triple every 0x0C. */
    for (int i = 0; i < 4; ++i) {
        const uint32_t base = 0x0Cu + 0x0Cu * static_cast<uint32_t>(i);
        if (offset == base + 0u) return { RegKind::TcntbN, i };
        if (offset == base + 4u) return { RegKind::TcmpbN, i };
        if (offset == base + 8u) return { RegKind::TcntoN, i };
    }
    /* S3C2410A UM p.10-19: TCNTB4 0x5100003C and TCNTO4 0x51000040; timer 4
       has no compare buffer. */
    if (offset == 0x3Cu) return { RegKind::TcntbN, 4 };
    if (offset == 0x40u) return { RegKind::TcntoN, 4 };
    return { RegKind::OutOfRange, 0 };
}

void S3C2410Timer::SetUnits(int n) {
    const uint64_t presc = (n <= 1)
        ? ((tcfg0_      ) & 0xFFu) + 1u
        : ((tcfg0_ >> 8 ) & 0xFFu) + 1u;

    const uint32_t mux = (tcfg1_ >> (n * 4)) & 0xFu;
    if (mux >= 4u) {
        emu_.Get<Fatal>().Die("S3C2410Timer: timer %d MUX %u selects external "
                              "TCLK, which CERF does not model", n, mux);
    }
    const uint64_t pclk = clocks_->PclkHz();
    const uint64_t cycles_per_tick_num = clock_->CpuHz() * presc * (1ull << (mux + 1));
    const uint64_t g = std::gcd(pclk, cycles_per_tick_num);
    TimerState& t = timers_[n];
    t.tk_unit  = pclk / g;
    t.cyc_unit = cycles_per_tick_num / g;
    if ((t.cyc_unit - 1u) > UINT64_MAX / t.tk_unit ||
        (t.tk_unit - 1u) > (UINT64_MAX - t.tk_unit) / t.cyc_unit) {
        emu_.Get<Fatal>().Die("S3C2410Timer: timer %d tick ratio %llu:%llu "
                              "overflows the 64-bit scale", n,
                              static_cast<unsigned long long>(t.tk_unit),
                              static_cast<unsigned long long>(t.cyc_unit));
    }
}

uint32_t S3C2410Timer::CountAt(int n, uint64_t now) const {
    const TimerState& t = timers_[n];
    if (!t.running || gated_) return t.count;
    const uint64_t since = TicksSince(t, now);
    if (since >= t.zero_tick) return 0;
    return static_cast<uint32_t>(t.zero_tick - since);
}

void S3C2410Timer::SetCount(int n, uint64_t now, uint32_t count) {
    TimerState& t = timers_[n];
    t.count         = count;
    t.origin_cycles = now;
    t.zero_tick     = count;
}

void S3C2410Timer::ArmTimer(int n) {
    const TimerState& t = timers_[n];
    if (!t.running || gated_) {
        clock_->Disarm(event_[n]);
        return;
    }
    clock_->Arm(event_[n],
                t.origin_cycles + ScaleU64Ceil(t.zero_tick, t.cyc_unit, t.tk_unit));
}

void S3C2410Timer::ApplyTconWrite(uint32_t new_tcon, uint64_t now) {
    for (int i = 0; i < 5; ++i) {
        const TimerBits& bits = kTcon[i];
        TimerState& t = timers_[i];
        const bool start  = ((new_tcon >> bits.start)         & 1u) != 0;
        const bool manual = ((new_tcon >> bits.manual_update) & 1u) != 0;

        t.auto_reload = ((new_tcon >> bits.auto_reload) & 1u) != 0;

        if (manual) SetCount(i, now, t.tcntb);
        if (!start) {
            if (t.running) Reanchor(i, now);
            t.running = false;
        } else if (!t.running && t.count != 0) {
            SetCount(i, now, t.count);
            t.running = true;
        }
        ArmTimer(i);
    }
}

/* S3C2410A UM p.10-11/10-12/10-13/10-15/10-19: TCFG0, TCFG1, TCON, TCNTBn,
   TCMPBn and TCNTOn all carry a reset value of 0x00000000. */
void S3C2410Timer::OnResetLine() {
    tcfg0_ = 0;
    tcfg1_ = 0;
    tcon_  = 0;
    gated_ = !clocks_->PwmTimerClockOn();
    for (int i = 0; i < 5; ++i) {
        timers_[i] = TimerState{};
        SetUnits(i);
        ArmTimer(i);
    }
}

void S3C2410Timer::OnRateChange() {
    const uint64_t now = Now();
    for (int i = 0; i < 5; ++i) Reanchor(i, now);
    gated_ = !clocks_->PwmTimerClockOn();
    for (int i = 0; i < 5; ++i) {
        SetUnits(i);
        ArmTimer(i);
    }
}

void S3C2410Timer::OnMatch(int n) {
    TimerState& t = timers_[n];
    if (t.auto_reload && t.tcntb != 0u) {
        t.zero_tick += t.tcntb;
        t.count      = t.tcntb;
    } else {
        t.count   = 0;
        t.running = false;
    }
    ArmTimer(n);
    emu_.Get<IrqController>().AssertIrq(kIrqTimerN[n]);
}

uint32_t S3C2410Timer::ReadWord(uint32_t addr) {
    const uint32_t off = addr - MmioBase();
    const auto dec = DecodeReg(off);

    switch (dec.kind) {
        case RegKind::Tcfg0:  return tcfg0_;
        case RegKind::Tcfg1:  return tcfg1_;
        case RegKind::Tcon:   return tcon_;
        case RegKind::TcntbN: return timers_[dec.timer_idx].tcntb;
        case RegKind::TcmpbN: return timers_[dec.timer_idx].tcmpb;
        case RegKind::TcntoN: return CountAt(dec.timer_idx, Now());
        case RegKind::OutOfRange:
            HaltUnsupportedAccess("ReadWord", addr, 0);
    }
    HaltUnsupportedAccess("ReadWord", addr, 0);
}

void S3C2410Timer::WriteWord(uint32_t addr, uint32_t value) {
    const uint32_t off = addr - MmioBase();
    const auto dec = DecodeReg(off);

    switch (dec.kind) {
        case RegKind::Tcfg0: {
            LOG(SocTimer, "S3C2410Timer: TCFG0 <- 0x%08X\n", value);
            const uint64_t now = Now();
            for (int i = 0; i < 5; ++i) Reanchor(i, now);
            tcfg0_ = value;
            for (int i = 0; i < 5; ++i) {
                SetUnits(i);
                ArmTimer(i);
            }
            break;
        }
        case RegKind::Tcfg1: {
            LOG(SocTimer, "S3C2410Timer: TCFG1 <- 0x%08X\n", value);
            const uint32_t dma_mode = (value >> 20) & 0xFu;
            if (dma_mode != 0u) {
                emu_.Get<Fatal>().Die(
                    "S3C2410Timer: TCFG1 DMA mode %u routes a timer request "
                    "to the DMA controller, which CERF does not model",
                    dma_mode);
            }
            const uint64_t now = Now();
            for (int i = 0; i < 5; ++i) Reanchor(i, now);
            tcfg1_ = value;
            for (int i = 0; i < 5; ++i) {
                SetUnits(i);
                ArmTimer(i);
            }
            break;
        }
        case RegKind::Tcon:
#if CERF_DEV_MODE
            LOG(SocTimer, "S3C2410Timer: TCON 0x%08X -> 0x%08X\n", tcon_, value);
#endif
            ApplyTconWrite(value, Now());
            tcon_ = value;
            break;
        case RegKind::TcntbN:
#if CERF_DEV_MODE
            LOG(SocTimer, "S3C2410Timer: TCNTB%d <- 0x%X\n", dec.timer_idx,
                value & kCountMask);
#endif
            timers_[dec.timer_idx].tcntb = value & kCountMask;
            break;
        case RegKind::TcmpbN:
            timers_[dec.timer_idx].tcmpb = value & kCountMask;
            break;
        case RegKind::TcntoN:
            break;
        case RegKind::OutOfRange:
            HaltUnsupportedAccess("WriteWord", addr, value);
    }
}

void S3C2410Timer::SaveState(StateWriter& w) {
    const uint64_t now = Now();
    w.Write("tcfg0", tcfg0_);
    w.Write("tcfg1", tcfg1_);
    w.Write("tcon", tcon_);
    for (int i = 0; i < 5; ++i) {
        const TimerState& t = timers_[i];
        w.Write("tcntb", t.tcntb);
        w.Write("tcmpb", t.tcmpb);
        w.Write<uint8_t>("running", t.running ? 1u : 0u);
        w.Write<uint8_t>("auto_reload", t.auto_reload ? 1u : 0u);
        w.Write<uint32_t>("count", CountAt(i, now));
    }
}

void S3C2410Timer::RestoreState(StateReader& r) {
    const uint64_t now = Now();
    r.Read("tcfg0", tcfg0_);
    r.Read("tcfg1", tcfg1_);
    r.Read("tcon", tcon_);
    for (int i = 0; i < 5; ++i) {
        TimerState& t = timers_[i];
        r.Read("tcntb", t.tcntb);
        r.Read("tcmpb", t.tcmpb);
        uint8_t running = 0, auto_reload = 0;
        r.Read("running", running);
        r.Read("auto_reload", auto_reload);
        uint32_t count = 0;
        r.Read("count", count);
        t.running     = (running != 0);
        t.auto_reload = (auto_reload != 0);
        SetUnits(i);
        SetCount(i, now, count);
        ArmTimer(i);
    }
}

}

REGISTER_SERVICE(S3C2410Timer);
