#include "../../peripherals/peripheral_base.h"

#include "../../boards/board_context.h"
#include "s3c2410_id.h"
#include "../../core/cerf_emulator.h"
#include "../../core/fatal.h"
#include "../../core/log.h"
#include "../../jit/guest_cycle_clock.h"
#include "../../peripherals/peripheral_dispatcher.h"
#include "../../state/state_stream.h"
#include "../guest_cpu_reset.h"
#include "../irq_controller.h"
#include "s3c2410_clocks.h"
#include "s3c2410_timer_prescalers.h"
#include "s3c2410_timer_regs.h"

#include <cstdint>

namespace {

using namespace S3C2410TimerRegs;

class S3C2410Timer : public Peripheral {
public:
    using Peripheral::Peripheral;

    bool ShouldRegister() override {
        auto* bd = emu_.TryGet<BoardContext>();
        return bd && bd->GetSocId() == SocId::S3c2410;
    }
    void OnReady() override {
        clock_      = &emu_.Get<GuestCycleClock>();
        prescalers_ = &emu_.Get<S3C2410TimerPrescalers>();
        for (int i = 0; i < 5; ++i) event_[i] = clock_->Add([this, i] { OnMatch(i); });
        emu_.Get<S3C2410Clocks>().RegisterRateListener([this] { OnRateChange(); });
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
    struct TimerState {
        uint32_t tcntb          = 0;
        uint32_t tcmpb          = 0;
        bool     running        = false;
        bool     auto_reload    = false;
        bool     reload_pending = false;
        uint32_t count          = 0;
        uint64_t start_tick     = 0;
    };

    uint64_t Now() const { return clock_->Cycles(); }

    static int GroupOf(int n) { return n <= 1 ? 0 : 1; }

    void     RequireDividerMux(int n, uint32_t tcfg1) const;
    void     RequireOneDividerTap() const;
    void     RequirePwmClock(const char* access, uint32_t addr) const;
    uint64_t TickAt(int n, uint64_t cycle) const;
    uint64_t EdgeCycles(int n, uint64_t tick) const;
    uint32_t CountAt(int n, uint64_t now) const;
    void     StartPeriod(int n, uint64_t now);
    void     ArmTimer(int n);
    void     ApplyTconWrite(uint32_t new_tcon, uint64_t now);

    void OnMatch(int n);
    void WriteTcfg(uint32_t tcfg0, uint32_t tcfg1, uint64_t now);
    void OnRateChange();
    void OnResetLine();

    GuestCycleClock*        clock_      = nullptr;
    S3C2410TimerPrescalers* prescalers_ = nullptr;
    GuestCycleClock::Event* event_[5]   = {};
    uint32_t                tcfg0_      = 0;
    uint32_t                tcfg1_      = 0;
    uint32_t                tcon_       = 0;
    TimerState              timers_[5];
};

void S3C2410Timer::RequireDividerMux(int n, uint32_t tcfg1) const {
    const uint32_t mux = Mux(n, tcfg1);
    if (const char* why = UnmodelledMux(mux)) {
        emu_.Get<Fatal>().Die("S3C2410Timer: timer %d MUX %u %s", n, mux, why);
    }
}

uint64_t S3C2410Timer::TickAt(int n, uint64_t cycle) const {
    return prescalers_->PulsesAt(GroupOf(n), cycle) >> DividerShift(n, tcfg1_);
}

uint64_t S3C2410Timer::EdgeCycles(int n, uint64_t tick) const {
    return prescalers_->CycleOfPulse(GroupOf(n), tick << DividerShift(n, tcfg1_));
}

/* S3C2410A UM p.10-3 Figure 10-2: TCNTn holds its loaded value until the
   next timer-clock edge, steps down once per edge, and requests the interrupt
   as it reaches 0; an auto reload takes effect one edge after the 0. */
uint32_t S3C2410Timer::CountAt(int n, uint64_t now) const {
    const TimerState& t = timers_[n];
    if (!t.running) return t.count;
    const uint64_t tick = TickAt(n, now);
    if (tick < t.start_tick) return t.reload_pending ? 0u : t.count;
    const uint64_t since = tick - t.start_tick;
    if (since >= t.count) return 0;
    return static_cast<uint32_t>(t.count - since);
}

void S3C2410Timer::StartPeriod(int n, uint64_t now) {
    TimerState& t    = timers_[n];
    t.start_tick     = TickAt(n, now) + 1u;
    t.reload_pending = false;
}

void S3C2410Timer::ArmTimer(int n) {
    const TimerState& t = timers_[n];
    if (!t.running || prescalers_->Gated()) {
        clock_->Disarm(event_[n]);
        return;
    }
    clock_->Arm(event_[n], EdgeCycles(n, t.start_tick + t.count));
}

void S3C2410Timer::ApplyTconWrite(uint32_t new_tcon, uint64_t now) {
    for (int i = 0; i < 5; ++i) {
        const TimerBits& bits = kTcon[i];
        TimerState& t = timers_[i];
        const bool start  = TconBit(new_tcon, bits.start);
        const bool manual = TconBit(new_tcon, bits.manual_update);

        t.auto_reload = TconBit(new_tcon, bits.auto_reload);

        if (manual) {
            t.count = t.tcntb;
            if (t.running) StartPeriod(i, now);
        }
        if (!start) {
            if (t.running) {
                t.count          = CountAt(i, now);
                t.reload_pending = false;
            }
            t.running = false;
        } else if (!t.running && t.count != 0) {
            StartPeriod(i, now);
            t.running = true;
        }
        ArmTimer(i);
    }
    RequireOneDividerTap();
}

/* S3C2410A UM p.10-11/10-12/10-13/10-15/10-19: TCFG0, TCFG1, TCON, TCNTBn,
   TCMPBn and TCNTOn all carry a reset value of 0x00000000. */
void S3C2410Timer::OnResetLine() {
    tcfg0_ = 0;
    tcfg1_ = 0;
    tcon_  = 0;
    prescalers_->Restart(Now());
    for (int i = 0; i < 5; ++i) {
        timers_[i] = TimerState{};
        ArmTimer(i);
    }
}

void S3C2410Timer::WriteTcfg(uint32_t tcfg0, uint32_t tcfg1, uint64_t now) {
    for (int i = 0; i < 5; ++i) RequireDividerMux(i, tcfg1);
    for (int i = 0; i < 5; ++i) {
        if (!timers_[i].running) continue;
        const int g = GroupOf(i);
        if (Prescaler(g, tcfg0) != Prescaler(g, tcfg0_)) {
            emu_.Get<Fatal>().Die("S3C2410Timer: TCFG0 changes prescaler %d %u -> %u while "
                                  "timer %d runs; the prescaler phase across that change is "
                                  "not modelled", g, Prescaler(g, tcfg0_), Prescaler(g, tcfg0), i);
        }
        if (Mux(i, tcfg1) != Mux(i, tcfg1_)) {
            emu_.Get<Fatal>().Die("S3C2410Timer: TCFG1 changes running timer %d MUX %u -> %u; "
                                  "the timer clock across that switch is not modelled", i,
                                  Mux(i, tcfg1_), Mux(i, tcfg1));
        }
    }
    const uint32_t old_tcfg0 = tcfg0_;
    tcfg0_ = tcfg0;
    tcfg1_ = tcfg1;
    for (int g = 0; g < S3C2410TimerPrescalers::kGroups; ++g) {
        if (Prescaler(g, tcfg0) != Prescaler(g, old_tcfg0)) {
            prescalers_->Reload(g, Prescaler(g, tcfg0), now);
        }
    }
    for (int i = 0; i < 5; ++i) ArmTimer(i);
}

void S3C2410Timer::RequireOneDividerTap() const {
    for (int a = 0; a < 5; ++a) {
        for (int b = a + 1; b < 5; ++b) {
            if (!timers_[a].running || !timers_[b].running || GroupOf(a) != GroupOf(b) ||
                Mux(a, tcfg1_) == Mux(b, tcfg1_)) {
                continue;
            }
            emu_.Get<Fatal>().Die("S3C2410Timer: timers %d and %d of prescaler %d run on "
                                  "divider taps 1/%u and 1/%u; the divider output edge "
                                  "polarity is not modelled", a, b, GroupOf(a),
                                  1u << DividerShift(a, tcfg1_), 1u << DividerShift(b, tcfg1_));
        }
    }
}

void S3C2410Timer::OnRateChange() {
    prescalers_->OnRateChange(Now());
    for (int i = 0; i < 5; ++i) ArmTimer(i);
}

void S3C2410Timer::OnMatch(int n) {
    TimerState& t = timers_[n];
    if (t.auto_reload && t.tcntb != 0u) {
        t.start_tick     = t.start_tick + t.count + 1u;
        t.count          = t.tcntb;
        t.reload_pending = true;
    } else {
        t.count   = 0;
        t.running = false;
    }
    ArmTimer(n);
    emu_.Get<IrqController>().AssertIrq(kIrqTimerN[n]);
}

void S3C2410Timer::RequirePwmClock(const char* access, uint32_t addr) const {
    if (!prescalers_->Gated()) return;
    emu_.Get<Fatal>().Die("S3C2410Timer: %s at 0x%08X while CLKCON[8] gates PCLK into the "
                          "PWM timer; register access with that clock off is not modelled",
                          access, addr);
}

uint32_t S3C2410Timer::ReadWord(uint32_t addr) {
    RequirePwmClock("ReadWord", addr);
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
    RequirePwmClock("WriteWord", addr);
    const uint32_t off = addr - MmioBase();
    const auto dec = DecodeReg(off);

    switch (dec.kind) {
        case RegKind::Tcfg0: {
            LOG(SocTimer, "S3C2410Timer: TCFG0 <- 0x%08X\n", value);
            if ((value & kTcfg0DeadZone) != 0u) {
                emu_.Get<Fatal>().Die("S3C2410Timer: TCFG0 0x%08X sets dead zone length "
                                      "0x%02X, which CERF does not model", value,
                                      (value & kTcfg0DeadZone) >> 16);
            }
            if ((value & kTcfgReserved) != 0u) {
                emu_.Get<Fatal>().Die("S3C2410Timer: TCFG0 0x%08X sets reserved bits "
                                      "[31:24]", value);
            }
            WriteTcfg(value, tcfg1_, Now());
            break;
        }
        case RegKind::Tcfg1: {
            LOG(SocTimer, "S3C2410Timer: TCFG1 <- 0x%08X\n", value);
            /* S3C2410A UM printed p.10-12 TCFG1 DMA mode [23:20]: 0000 No select,
               0001-0101 Timer0-Timer4, 0110 Reserved. */
            const uint32_t dma_mode = DmaMode(value);
            if (dma_mode >= 7u) {
                emu_.Get<Fatal>().Die("S3C2410Timer: TCFG1 DMA mode %u is a code TCFG1 does "
                                      "not define", dma_mode);
            }
            if (dma_mode == 6u) {
                emu_.Get<Fatal>().Die("S3C2410Timer: TCFG1 DMA mode 6 is reserved");
            }
            if (dma_mode != 0u) {
                emu_.Get<Fatal>().Die("S3C2410Timer: TCFG1 DMA mode %u routes the timer %u "
                                      "request to the DMA controller, which CERF does not "
                                      "model", dma_mode, dma_mode - 1u);
            }
            if ((value & kTcfgReserved) != 0u) {
                emu_.Get<Fatal>().Die("S3C2410Timer: TCFG1 0x%08X sets reserved bits "
                                      "[31:24]", value);
            }
            WriteTcfg(tcfg0_, value, Now());
            break;
        }
        case RegKind::Tcon:
#if CERF_DEV_MODE
            LOG(SocTimer, "S3C2410Timer: TCON 0x%08X -> 0x%08X\n", tcon_, value);
#endif
            if ((value & kTconInverters) != 0u) {
                emu_.Get<Fatal>().Die("S3C2410Timer: TCON 0x%08X sets output inverter bits "
                                      "0x%08X for TOUT0-3, which CERF does not model",
                                      value, value & kTconInverters);
            }
            if ((value & kTconDeadZone) != 0u) {
                emu_.Get<Fatal>().Die("S3C2410Timer: TCON 0x%08X sets dead zone enable [4], "
                                      "which CERF does not model", value);
            }
            if ((value & kTconReserved) != 0u) {
                emu_.Get<Fatal>().Die("S3C2410Timer: TCON 0x%08X sets reserved bits 0x%08X",
                                      value, value & kTconReserved);
            }
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
    prescalers_->SaveState(w, now);
    for (int i = 0; i < 5; ++i) {
        const TimerState& t = timers_[i];
        const bool pending  = t.running && TickAt(i, now) < t.start_tick;
        w.Write("tcntb", t.tcntb);
        w.Write("tcmpb", t.tcmpb);
        w.Write<uint8_t>("running", t.running ? 1u : 0u);
        w.Write<uint8_t>("auto_reload", t.auto_reload ? 1u : 0u);
        w.Write<uint8_t>("pending", pending ? 1u : 0u);
        w.Write<uint8_t>("reload_pending", t.reload_pending ? 1u : 0u);
        w.Write<uint32_t>("count", pending ? t.count : CountAt(i, now));
    }
}

void S3C2410Timer::RestoreState(StateReader& r) {
    const uint64_t now = Now();
    r.Read("tcfg0", tcfg0_);
    r.Read("tcfg1", tcfg1_);
    r.Read("tcon", tcon_);
    prescalers_->RestoreState(r, tcfg0_, now);
    for (int i = 0; i < 5; ++i) {
        TimerState& t = timers_[i];
        r.Read("tcntb", t.tcntb);
        r.Read("tcmpb", t.tcmpb);
        uint8_t running = 0, auto_reload = 0, pending = 0, reload_pending = 0;
        r.Read("running", running);
        r.Read("auto_reload", auto_reload);
        r.Read("pending", pending);
        r.Read("reload_pending", reload_pending);
        uint32_t count = 0;
        r.Read("count", count);
        const uint64_t tick = TickAt(i, now);
        t.running        = (running != 0);
        t.auto_reload    = (auto_reload != 0);
        t.reload_pending = (reload_pending != 0) && (pending != 0);
        t.count          = count;
        t.start_tick     = pending != 0 ? tick + 1u : tick;
        ArmTimer(i);
    }
}

}

REGISTER_SERVICE(S3C2410Timer);
