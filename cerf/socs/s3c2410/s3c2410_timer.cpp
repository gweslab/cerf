#include "../../peripherals/peripheral_base.h"

#include "../../core/cerf_emulator.h"
#include "../../core/log.h"
#include "../../peripherals/peripheral_dispatcher.h"
#include "../irq_controller.h"
#include "../../boards/board_detector.h"

#include <atomic>
#include <chrono>
#include <cstdint>
#include <mutex>
#include <thread>

namespace {

constexpr uint64_t kPclkHz = 50750000ull;

struct TimerBits {
    int start;
    int manual_update;
    int auto_reload;
};
/* Timer 4 lacks INVERTER, so AUTO_RELOAD = nibble offset 2 (bit 22),
   not offset 3 like timers 0..3. */
constexpr TimerBits kTcon[5] = {
    /* timer 0 */ { 0,   1,   3  },
    /* timer 1 */ { 8,   9,   11 },
    /* timer 2 */ { 12,  13,  15 },
    /* timer 3 */ { 16,  17,  19 },
    /* timer 4 */ { 20,  21,  22 },
};

/* Source bit in S3C2410Intc SRCPND for each timer N. */
constexpr int kIrqTimerN[5] = { 10, 11, 12, 13, 14 };

class S3C2410Timer : public Peripheral {
public:
    using Peripheral::Peripheral;
    ~S3C2410Timer() override {
        stop_thread_.store(true, std::memory_order_release);
        if (tick_thread_.joinable()) tick_thread_.join();
    }

    bool ShouldRegister() override {
        auto* bd = emu_.TryGet<BoardDetector>();
        return bd && bd->GetSoc() == SocFamily::S3C2410;
    }
    void OnReady() override {
        emu_.Get<PeripheralDispatcher>().Register(this);
        tick_thread_ = std::thread(&S3C2410Timer::TickLoop, this);
    }

    uint32_t MmioBase() const override { return 0x51000000u; }
    uint32_t MmioSize() const override { return 0x00100000u; }

    uint32_t ReadWord (uint32_t addr) override;
    void     WriteWord(uint32_t addr, uint32_t value) override;

private:
    using Clock = std::chrono::steady_clock;

    enum class RegKind { Tcfg0, Tcfg1, Tcon, TcntbN, TcmpbN, TcntoN, OutOfRange };
    struct DecodedReg { RegKind kind; int timer_idx; };

    static DecodedReg DecodeReg(uint32_t offset);

    /* Per-timer compute helpers; caller holds state_mutex_. */
    uint64_t TimerFreqHz(int timer_idx) const;
    uint32_t ComputeTcntoLocked(int timer_idx, Clock::time_point now) const;

    /* TCON write parsing — drives the per-timer state machine. Caller
       holds state_mutex_. */
    void ApplyTconWrite(uint32_t new_tcon, Clock::time_point now);

    /* Tick thread main loop — wakes ~1 ms, asserts IRQs for any
       running timer that underflowed since last wake, advances
       last_load_time accordingly. */
    void TickLoop();

    struct TimerState {
        uint32_t          tcntb           = 0;
        uint32_t          tcmpb           = 0;
        bool              running         = false;
        bool              auto_reload     = false;
        Clock::time_point last_load_time  = {};
        /* Cached TCNTO at the moment we transition running 1→0, so
           subsequent reads of a stopped timer return the post-stop
           value rather than re-interpolating against stale
           last_load_time. */
        uint32_t          stopped_value   = 0;
    };

    mutable std::mutex   state_mutex_;
    uint32_t             tcfg0_  = 0;
    uint32_t             tcfg1_  = 0;
    uint32_t             tcon_   = 0;
    TimerState           timers_[5];

    std::thread          tick_thread_;
    std::atomic<bool>    stop_thread_{false};
};

S3C2410Timer::DecodedReg S3C2410Timer::DecodeReg(uint32_t offset) {
    if (offset == 0x00u) return { RegKind::Tcfg0, 0 };
    if (offset == 0x04u) return { RegKind::Tcfg1, 0 };
    if (offset == 0x08u) return { RegKind::Tcon,  0 };
    /* Timers 0..3: TCNTBn / TCMPBn / TCNTOn at +0x0C+0x0C*N, +0x10+0x0C*N,
       +0x14+0x0C*N. */
    for (int i = 0; i < 4; ++i) {
        const uint32_t base = 0x0Cu + 0x0Cu * static_cast<uint32_t>(i);
        if (offset == base + 0u) return { RegKind::TcntbN, i };
        if (offset == base + 4u) return { RegKind::TcmpbN, i };
        if (offset == base + 8u) return { RegKind::TcntoN, i };
    }
    /* Timer 4 — pair only (no TCMPB4) at +0x3C, +0x40. */
    if (offset == 0x3Cu) return { RegKind::TcntbN, 4 };
    if (offset == 0x40u) return { RegKind::TcntoN, 4 };
    return { RegKind::OutOfRange, 0 };
}

uint64_t S3C2410Timer::TimerFreqHz(int timer_idx) const {
    /* TCFG0[7:0]   = prescaler 0 (timers 0/1)
       TCFG0[15:8]  = prescaler 1 (timers 2/3/4)
       TCFG1[N*4 +:4] = mux for timer N (0=/2, 1=/4, 2=/8, 3=/16,
                                          4=TCLK external) */
    const uint64_t presc = (timer_idx <= 1)
        ? ((tcfg0_      ) & 0xFFu) + 1u
        : ((tcfg0_ >> 8 ) & 0xFFu) + 1u;

    const uint32_t mux = (tcfg1_ >> (timer_idx * 4)) & 0xFu;
    if (mux >= 4u) {
        LOG(Caution, "S3C2410Timer: timer %d mux %u (TCLK external) "
                "not modelled\n", timer_idx, mux);
        CerfFatalExit(CERF_FATAL_RUNTIME_ERROR);
    }
    /* mux 0..3 → divider 2,4,8,16 (= 1<<(mux+1)). */
    const uint64_t div = 1ull << (mux + 1);
    return kPclkHz / presc / div;
}

uint32_t S3C2410Timer::ComputeTcntoLocked(int timer_idx,
                                          Clock::time_point now) const {
    const TimerState& t = timers_[timer_idx];
    if (!t.running) return t.stopped_value;

    const auto elapsed_ns =
        std::chrono::duration_cast<std::chrono::nanoseconds>(
            now - t.last_load_time).count();
    const uint64_t freq = TimerFreqHz(timer_idx);
    const uint64_t elapsed_counts =
        (elapsed_ns <= 0)
            ? 0ull
            : (static_cast<uint64_t>(elapsed_ns) * freq / 1'000'000'000ull);

    if (elapsed_counts >= t.tcntb) {
        /* Underflow happened but the tick thread hasn't observed it
           yet; report 0. The next tick-thread wake will assert IRQ
           and reload last_load_time. */
        return 0u;
    }
    return static_cast<uint32_t>(t.tcntb - elapsed_counts);
}

void S3C2410Timer::ApplyTconWrite(uint32_t new_tcon, Clock::time_point now) {
    for (int i = 0; i < 5; ++i) {
        const TimerBits& bits = kTcon[i];
        const bool old_start  = ((tcon_     >> bits.start)         & 1u) != 0;
        const bool new_start  = ((new_tcon  >> bits.start)         & 1u) != 0;
        const bool new_manual = ((new_tcon  >> bits.manual_update) & 1u) != 0;
        const bool new_areload= ((new_tcon  >> bits.auto_reload)   & 1u) != 0;

        timers_[i].auto_reload = new_areload;

        if (new_manual) {
            /* Manual update: TCNTOn loads from TCNTBn. Per BSP
               timer.c the OAL sets MU then in the next write clears
               MU + sets START — the MU step alone does not start the
               countdown. */
            timers_[i].last_load_time = now;
            timers_[i].running        = false;
            timers_[i].stopped_value  = timers_[i].tcntb;
        } else if (!old_start && new_start) {
            /* 0→1 START with MU clear: countdown begins from TCNTBn. */
            timers_[i].last_load_time = now;
            timers_[i].running        = true;
        } else if (old_start && !new_start) {
            /* 1→0 STOP: cache the post-stop count so subsequent reads
               return that value instead of re-interpolating against
               stale last_load_time. */
            timers_[i].stopped_value = ComputeTcntoLocked(i, now);
            timers_[i].running       = false;
        }
        /* No transition — leave running / last_load_time alone. */
    }
}

uint32_t S3C2410Timer::ReadWord(uint32_t addr) {
    const uint32_t off = addr - MmioBase();
    const auto dec = DecodeReg(off);

    uint32_t value = 0;
    {
        std::lock_guard<std::mutex> lk(state_mutex_);
        switch (dec.kind) {
            case RegKind::Tcfg0:  value = tcfg0_; break;
            case RegKind::Tcfg1:  value = tcfg1_; break;
            case RegKind::Tcon:   value = tcon_;  break;
            case RegKind::TcntbN: value = timers_[dec.timer_idx].tcntb; break;
            case RegKind::TcmpbN: value = timers_[dec.timer_idx].tcmpb; break;
            case RegKind::TcntoN: value = ComputeTcntoLocked(dec.timer_idx, Clock::now()); break;
            case RegKind::OutOfRange:
                HaltUnsupportedAccess("ReadWord", addr, 0);  /* noreturn */
        }
    }

    return value;
}

void S3C2410Timer::WriteWord(uint32_t addr, uint32_t value) {
    const uint32_t off = addr - MmioBase();
    const auto dec = DecodeReg(off);

    {
        std::lock_guard<std::mutex> lk(state_mutex_);
        switch (dec.kind) {
            case RegKind::Tcfg0:  tcfg0_ = value; break;
            case RegKind::Tcfg1:  tcfg1_ = value; break;
            case RegKind::Tcon:
                ApplyTconWrite(value, Clock::now());
                tcon_ = value;
                break;
            case RegKind::TcntbN: timers_[dec.timer_idx].tcntb = value; break;
            case RegKind::TcmpbN: timers_[dec.timer_idx].tcmpb = value; break;
            case RegKind::TcntoN:
                /* Read-only on the chip — silently drop writes. The
                   kernel would never write here intentionally; halting
                   would falsely flag corrupt code. */
                break;
            case RegKind::OutOfRange:
                HaltUnsupportedAccess("WriteWord", addr, value);  /* noreturn */
        }
    }
}

void S3C2410Timer::TickLoop() {
    auto& irq = emu_.Get<IrqController>();

    while (!stop_thread_.load(std::memory_order_acquire)) {
        std::this_thread::sleep_for(std::chrono::milliseconds(1));

        /* Decide which timers underflowed under the lock; AssertIrq
           outside the lock so the intc's mutex isn't taken under ours
           (avoids any future cross-locking surprise). */
        struct Fire { int timer_idx; int irq_source; };
        Fire   fires[5];
        size_t fire_count = 0;
        {
            std::lock_guard<std::mutex> lk(state_mutex_);
            const auto now = Clock::now();
            for (int i = 0; i < 5; ++i) {
                TimerState& t = timers_[i];
                if (!t.running) continue;

                const auto elapsed_ns =
                    std::chrono::duration_cast<std::chrono::nanoseconds>(
                        now - t.last_load_time).count();
                if (elapsed_ns <= 0) continue;

                const uint64_t freq = TimerFreqHz(i);
                const uint64_t elapsed_counts =
                    static_cast<uint64_t>(elapsed_ns) * freq /
                    1'000'000'000ull;

                if (elapsed_counts < t.tcntb) continue;

                fires[fire_count++] = { i, kIrqTimerN[i] };

                if (t.auto_reload) {
                    t.last_load_time = now;
                } else {
                    t.running       = false;
                    t.stopped_value = 0;
                }
            }
        }

        for (size_t k = 0; k < fire_count; ++k) {
            irq.AssertIrq(fires[k].irq_source);
        }
    }
}

}  /* namespace */

REGISTER_SERVICE(S3C2410Timer);
