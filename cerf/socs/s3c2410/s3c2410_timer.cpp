#include "../../peripherals/peripheral_base.h"

#include "../../boards/board_context.h"
#include "s3c2410_id.h"
#include "../../core/cerf_emulator.h"
#include "../../core/fatal.h"
#include "../../core/log.h"
#include "../../jit/guest_cycle_clock.h"
#include "../../peripherals/peripheral_dispatcher.h"
#include "../../state/state_stream.h"
#include "../cycle_anchored_counter.h"
#include "../guest_cpu_reset.h"
#include "../irq_controller.h"
#include "s3c2410_clocks.h"

#include <cstdint>

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
        clocks_->RegisterRateListener([this] { Reconfigure(tcfg0_, tcfg1_, Now()); });
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
        uint32_t tcntb          = 0;
        uint32_t tcmpb          = 0;
        bool     running        = false;
        bool     auto_reload    = false;
        bool     reload_pending = false;
        uint32_t count          = 0;
        uint64_t start_tick     = 0;
        uint64_t epoch_tick     = 0;
        uint64_t ratio_cycles   = 0;
        uint64_t ratio_ticks    = 0;
        uint64_t freeze_cycle   = 0;
        CycleAnchoredCounter epoch;
    };

    uint64_t Now() const { return clock_->Cycles(); }

    void     SetUnits(int n);
    uint64_t ChannelDivisor(int n) const;
    uint64_t TickAt(const TimerState& t, uint64_t cycles) const;
    uint64_t EdgeCycles(const TimerState& t, uint64_t tick) const;
    uint32_t CountAt(int n, uint64_t now) const;
    void     StartPeriod(int n, uint64_t now);
    void     Reanchor(int n, uint64_t now);
    void     ArmTimer(int n);
    void     ApplyTconWrite(uint32_t new_tcon, uint64_t now);

    void OnMatch(int n);
    void Reconfigure(uint32_t tcfg0, uint32_t tcfg1, uint64_t now);
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

uint64_t S3C2410Timer::ChannelDivisor(int n) const {
    const uint64_t presc = (n <= 1)
        ? ((tcfg0_      ) & 0xFFu) + 1u
        : ((tcfg0_ >> 8 ) & 0xFFu) + 1u;
    const uint32_t mux = (tcfg1_ >> (n * 4)) & 0xFu;
    return presc * (1ull << (mux + 1));
}

void S3C2410Timer::SetUnits(int n) {
    const uint32_t mux = (tcfg1_ >> (n * 4)) & 0xFu;
    if (mux >= 4u) {
        emu_.Get<Fatal>().Die("S3C2410Timer: timer %d MUX %u selects external "
                              "TCLK, which CERF does not model", n, mux);
    }
    TimerState& t = timers_[n];
    t.ratio_ticks  = clocks_->PclkHz();
    t.ratio_cycles = clocks_->CoreClockHz() * ChannelDivisor(n);
    if (!t.epoch.SetRatio(t.ratio_cycles, t.ratio_ticks)) {
        emu_.Get<Fatal>().Die("S3C2410Timer: timer %d tick ratio %llu:%llu "
                              "overflows the 64-bit scale", n,
                              static_cast<unsigned long long>(t.ratio_ticks),
                              static_cast<unsigned long long>(t.ratio_cycles));
    }
}

/* S3C2410A UM printed p. 7-21 CLKCON [8]: "Control PCLK into PWMTIMER block". */
uint64_t S3C2410Timer::TickAt(const TimerState& t, uint64_t cycles) const {
    if (gated_ && cycles > t.freeze_cycle) cycles = t.freeze_cycle;
    if (cycles < t.epoch.AnchorCycle()) return t.epoch_tick - 1u;
    return t.epoch_tick + t.epoch.TicksSince(cycles);
}

uint64_t S3C2410Timer::EdgeCycles(const TimerState& t, uint64_t tick) const {
    if (tick < t.epoch_tick) {
        emu_.Get<Fatal>().Die("S3C2410Timer: edge %llu precedes the epoch edge %llu",
                              static_cast<unsigned long long>(tick),
                              static_cast<unsigned long long>(t.epoch_tick));
    }
    return t.epoch.CycleOfTick(tick - t.epoch_tick);
}

/* S3C2410A UM p.10-3 Figure 10-2: TCNTn holds its loaded value until the
   next timer-clock edge, steps down once per edge, and requests the interrupt
   as it reaches 0; an auto reload takes effect one edge after the 0. */
uint32_t S3C2410Timer::CountAt(int n, uint64_t now) const {
    const TimerState& t = timers_[n];
    if (!t.running) return t.count;
    const uint64_t tick = TickAt(t, now);
    if (tick < t.start_tick) return t.reload_pending ? 0u : t.count;
    const uint64_t since = tick - t.start_tick;
    if (since >= t.count) return 0;
    return static_cast<uint32_t>(t.count - since);
}

void S3C2410Timer::StartPeriod(int n, uint64_t now) {
    TimerState& t    = timers_[n];
    t.start_tick     = TickAt(t, now) + 1u;
    t.reload_pending = false;
}

void S3C2410Timer::Reanchor(int n, uint64_t now) {
    TimerState& t = timers_[n];
    const bool pending = t.running && TickAt(t, now) < t.start_tick;
    if (!pending) {
        t.count          = CountAt(n, now);
        t.reload_pending = false;
    }
    t.epoch.Anchor(now, 0u);
    t.epoch_tick   = 0;
    t.freeze_cycle = now;
    t.start_tick = pending ? 1u : 0u;
}

void S3C2410Timer::ArmTimer(int n) {
    const TimerState& t = timers_[n];
    if (!t.running || gated_) {
        clock_->Disarm(event_[n]);
        return;
    }
    const uint64_t zero = t.start_tick + t.count;
    clock_->Arm(event_[n], zero < t.epoch_tick ? Now() : EdgeCycles(t, zero));
}

void S3C2410Timer::ApplyTconWrite(uint32_t new_tcon, uint64_t now) {
    for (int i = 0; i < 5; ++i) {
        const TimerBits& bits = kTcon[i];
        TimerState& t = timers_[i];
        const bool start  = ((new_tcon >> bits.start)         & 1u) != 0;
        const bool manual = ((new_tcon >> bits.manual_update) & 1u) != 0;

        t.auto_reload = ((new_tcon >> bits.auto_reload) & 1u) != 0;

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
}

/* S3C2410A UM p.10-11/10-12/10-13/10-15/10-19: TCFG0, TCFG1, TCON, TCNTBn,
   TCMPBn and TCNTOn all carry a reset value of 0x00000000. */
void S3C2410Timer::OnResetLine() {
    tcfg0_ = 0;
    tcfg1_ = 0;
    tcon_  = 0;
    gated_ = !clocks_->PwmTimerClockOn();
    const uint64_t now = Now();
    for (int i = 0; i < 5; ++i) {
        timers_[i] = TimerState{};
        timers_[i].epoch.Anchor(now, 0u);
        timers_[i].freeze_cycle = now;
        SetUnits(i);
        ArmTimer(i);
    }
}

void S3C2410Timer::Reconfigure(uint32_t tcfg0, uint32_t tcfg1, uint64_t now) {
    const bool gated = !clocks_->PwmTimerClockOn();
    tcfg0_ = tcfg0;
    tcfg1_ = tcfg1;
    for (int i = 0; i < 5; ++i) {
        TimerState& t = timers_[i];
        const TimerState before = t;
        SetUnits(i);
        if (gated == gated_ && t.ratio_cycles == before.ratio_cycles &&
            t.ratio_ticks == before.ratio_ticks)
            continue;
        t = before;
        Reanchor(i, now);
        SetUnits(i);
    }
    gated_ = gated;
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
            Reconfigure(value, tcfg1_, Now());
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
            Reconfigure(tcfg0_, value, Now());
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
        const TimerState& t    = timers_[i];
        const uint64_t    tick = TickAt(t, now);
        const bool pending = t.running && tick < t.start_tick;
        w.Write("tcntb", t.tcntb);
        w.Write("tcmpb", t.tcmpb);
        w.Write<uint8_t>("running", t.running ? 1u : 0u);
        w.Write<uint8_t>("auto_reload", t.auto_reload ? 1u : 0u);
        w.Write<uint8_t>("pending", pending ? 1u : 0u);
        w.Write<uint8_t>("reload_pending", t.reload_pending ? 1u : 0u);
        w.Write<uint32_t>("count", pending ? t.count : CountAt(i, now));
        w.Write<uint64_t>("to_next_edge",
                          gated_ ? t.epoch.CycleOfTick(1u) - t.epoch.AnchorCycle()
                                 : EdgeCycles(t, tick + 1u) - now);
    }
}

void S3C2410Timer::RestoreState(StateReader& r) {
    const uint64_t now = Now();
    r.Read("tcfg0", tcfg0_);
    r.Read("tcfg1", tcfg1_);
    r.Read("tcon", tcon_);
    for (int i = 0; i < 5; ++i) {
        const uint32_t mux = (tcfg1_ >> (i * 4)) & 0xFu;
        if (mux >= 4u) r.Reject("timer %d MUX %u selects external TCLK", i, mux);
    }
    const uint32_t dma_mode = (tcfg1_ >> 20) & 0xFu;
    if (dma_mode != 0u) r.Reject("TCFG1 DMA mode %u", dma_mode);
    gated_ = !clocks_->PwmTimerClockOn();
    for (int i = 0; i < 5; ++i) {
        TimerState& t = timers_[i];
        r.Read("tcntb", t.tcntb);
        r.Read("tcmpb", t.tcmpb);
        uint8_t running = 0, auto_reload = 0, pending = 0, reload_pending = 0;
        r.Read("running", running);
        r.Read("auto_reload", auto_reload);
        r.Read("pending", pending);
        r.Read("reload_pending", reload_pending);
        uint32_t count        = 0;
        uint64_t to_next_edge = 0;
        r.Read("count", count);
        r.Read("to_next_edge", to_next_edge);
        if (t.tcntb > kCountMask || count > kCountMask)
            r.Reject("timer %d count 0x%X or TCNTB 0x%X is past 16 bits", i, count, t.tcntb);
        const bool tcon_reload = ((tcon_ >> kTcon[i].auto_reload) & 1u) != 0u;
        if ((auto_reload != 0u) != tcon_reload)
            r.Reject("timer %d auto reload %u disagrees with TCON 0x%08X", i, auto_reload, tcon_);
        SetUnits(i);
        t.epoch.Anchor(0u, 0u);
        const uint64_t edge = t.epoch.CycleOfTick(1u);
        if (to_next_edge == 0u || to_next_edge > edge)
            r.Reject("timer %d next edge %llu cycles away is outside one edge period of %llu",
                     i, static_cast<unsigned long long>(to_next_edge),
                     static_cast<unsigned long long>(edge));
        t.running        = (running != 0);
        t.auto_reload    = (auto_reload != 0);
        t.reload_pending = (reload_pending != 0) && (pending != 0);
        t.count          = count;
        t.epoch.Anchor(now + to_next_edge, 0u);
        t.epoch_tick     = 1;
        t.freeze_cycle   = now;
        t.start_tick     = pending != 0 ? 1u : 0u;
        ArmTimer(i);
    }
}

}

REGISTER_SERVICE(S3C2410Timer);
