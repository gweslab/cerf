#include "pr31x00_rtc.h"

#include "pr31x00_intc.h"

#include "../../boards/board_context.h"
#include "pr31500_id.h"
#include "pr31700_id.h"
#include "../../core/cerf_emulator.h"
#include "../../peripherals/peripheral_dispatcher.h"
#include "../../state/emulation_freeze.h"
#include "../../state/state_stream.h"

#include <algorithm>
#include <cstdint>

namespace {

constexpr uint32_t kBase = 0x10C00140u;

constexpr uint32_t kOffRtcHi    = 0x00u;   /* $140 read-only RTC[39:32]   */
constexpr uint32_t kOffRtcLow   = 0x04u;   /* $144 read-only RTC[31:0]    */
constexpr uint32_t kOffAlarmHi  = 0x08u;   /* $148 ARARM[39:32]           */
constexpr uint32_t kOffAlarmLow = 0x0Cu;   /* $14C ARARM[31:0]            */
constexpr uint32_t kOffTimerCtl = 0x10u;   /* $150                        */
constexpr uint32_t kOffPeriodic = 0x14u;   /* $154                        */

/* The RTC counter is 40 bits wide (§15.4.1) and is clocked by the 32 kHz input
   pin (§15.4.3 ENTESTCLK). 2^40 / 32768 Hz = 388.4 days, which is the rollover
   period §15.4.3 ENRTCTST quotes as "388 days". */
constexpr uint64_t kMask40 = 0xFFFFFFFFFFull;

/* Timer Control (§15.4.3): FREEZEPRE<7> FREEZERTC<6> FREEZETIMER<5> ENPERTIMER<4>
   RTCCLR<3> TESTC8MS<2> ENTESTCLK<1> ENRTCTST<0>; bits 31-8 reserved. */
constexpr uint32_t kRtcClr           = 1u << 3;
constexpr uint32_t kEnPerTimer       = 1u << 4;
constexpr uint32_t kTimerCtlReserved = 0xFFFFFF00u;
constexpr uint32_t kTimerCtlUnmodeled = 0xE7u;   /* except RTCCLR<3> and ENPERTIMER<4> */

/* Interrupt Status 5 (§8.3.5), Status set index 4. */
constexpr uint32_t kStatusSet = 4u;
constexpr uint32_t kRtcInt    = 1u << 31;   /* counter reaches $FFFFFFFFFF */
constexpr uint32_t kAlarmInt  = 1u << 30;   /* counter equals ALARM[39:0]  */
constexpr uint32_t kPerInt    = 1u << 29;   /* Periodic Timer reaches zero  */

/* Periodic Timer (§15.4.4): PERCNT[15:0]<31:16> read-only, PERVAL[15:0]<15:0> R/W;
   Interrupt Rate = (PERVAL + 1) / f_TIMERCLK. TIMERCLK = CLK/32 (§15.1), = 1.152 MHz
   at the 36.864 MHz CLK (§15.3.2). */
constexpr uint32_t kPervalMask = 0xFFFFu;
constexpr uint64_t kTimerClkHz = 1152000u;
constexpr uint64_t kNsPerSec   = 1000000000ull;

}  /* namespace */

bool Pr31x00Rtc::ShouldRegister() {
    auto* bd = emu_.TryGet<BoardContext>();
    if (!bd) return false;
    const std::string_view soc = bd->GetSocId();
    return soc == SocId::Pr31500 || soc == SocId::Pr31700;
}

void Pr31x00Rtc::OnReady() {
    intc_ = &emu_.Get<Pr31x00Intc>();
    emu_.Get<PeripheralDispatcher>().Register(this);
    anchor_ = Clock::now();
    worker_ = std::thread([this] { WorkerLoop(); });
}

uint64_t Pr31x00Rtc::CountLocked() const {
    if (rtc_clr_) return 0;
    const uint64_t ticks =
        std::chrono::duration_cast<RtcTicks>(Clock::now() - anchor_).count();
    return (base_ticks_ + ticks) & kMask40;
}

Pr31x00Rtc::Clock::time_point Pr31x00Rtc::TimeAtCountLocked(uint64_t target) const {
    return anchor_ + std::chrono::duration_cast<Clock::duration>(
                         RtcTicks{(target - base_ticks_) & kMask40});
}

Pr31x00Rtc::Clock::duration Pr31x00Rtc::PeriodLocked() const {
    const uint64_t ns = (static_cast<uint64_t>(perval_) + 1u) * kNsPerSec / kTimerClkHz;
    return std::chrono::duration_cast<Clock::duration>(std::chrono::nanoseconds(ns));
}

uint32_t Pr31x00Rtc::PerCntLocked() const {
    if (!periodic_enabled_) return perval_;
    const auto now = Clock::now();
    if (now >= periodic_next_) return 0;
    const uint64_t rem_ns = std::chrono::duration_cast<std::chrono::nanoseconds>(
                                periodic_next_ - now).count();
    const uint64_t ticks = rem_ns * kTimerClkHz / kNsPerSec;
    return static_cast<uint32_t>(std::min<uint64_t>(ticks, perval_));
}

void Pr31x00Rtc::EvaluateLocked() {
    const auto now = Clock::now();
    if (periodic_enabled_ && now >= periodic_next_) {
        intc_->SetPending(kStatusSet, kPerInt);
        do { periodic_next_ += PeriodLocked(); } while (periodic_next_ <= now);
    }
    if (rtc_clr_) return;
    if (alarm_armed_ && !alarm_fired_ && now >= TimeAtCountLocked(alarm_)) {
        alarm_fired_ = true;
        intc_->SetPending(kStatusSet, kAlarmInt);
    }
    if (!rollover_fired_ && now >= TimeAtCountLocked(kMask40)) {
        rollover_fired_ = true;
        intc_->SetPending(kStatusSet, kRtcInt);
    }
}

void Pr31x00Rtc::NotifyWorker() {
    { std::lock_guard<std::mutex> g(cv_mtx_); rearm_ = true; }
    cv_.notify_all();
}

void Pr31x00Rtc::StopWorker() {
    if (!worker_.joinable()) return;
    stop_.store(true);
    NotifyWorker();
    worker_.join();
}

void Pr31x00Rtc::WorkerLoop() {
    auto& freeze = emu_.Get<EmulationFreeze>();
    while (!stop_.load()) {
        Clock::time_point deadline = Clock::time_point::max();
        {
            auto frozen = freeze.WorkerSection();
            std::lock_guard<std::mutex> lk(mtx_);
            EvaluateLocked();
            if (!rtc_clr_) {
                if (!rollover_fired_) deadline = TimeAtCountLocked(kMask40);
                if (alarm_armed_ && !alarm_fired_) {
                    deadline = std::min(deadline, TimeAtCountLocked(alarm_));
                }
            }
            if (periodic_enabled_) deadline = std::min(deadline, periodic_next_);
        }
        std::unique_lock<std::mutex> lk(cv_mtx_);
        const auto woke = [this] { return stop_.load() || rearm_; };
        if (deadline == Clock::time_point::max()) {
            cv_.wait(lk, woke);
        } else {
            cv_.wait_until(lk, deadline, woke);
        }
        rearm_ = false;
    }
}

uint32_t Pr31x00Rtc::ReadWord(uint32_t addr) {
    std::lock_guard<std::mutex> lk(mtx_);
    const uint32_t off = addr - kBase;
    switch (off) {
        case kOffRtcHi:    return static_cast<uint32_t>(CountLocked() >> 32);
        case kOffRtcLow:   return static_cast<uint32_t>(CountLocked() & 0xFFFFFFFFu);
        case kOffAlarmHi:  return static_cast<uint32_t>(alarm_ >> 32);
        case kOffAlarmLow: return static_cast<uint32_t>(alarm_ & 0xFFFFFFFFu);
        case kOffTimerCtl: return timer_ctl_;
        case kOffPeriodic: return (PerCntLocked() << 16) | perval_;
        default:           HaltUnsupportedAccess("PR31x00 RTC ReadWord", addr, 0);
    }
}

void Pr31x00Rtc::WriteWord(uint32_t addr, uint32_t value) {
    std::lock_guard<std::mutex> lk(mtx_);
    const uint32_t off = addr - kBase;
    switch (off) {
        case kOffRtcHi:
        case kOffRtcLow:
            /* The RTC counter is read-only (§15.4.1). */
            HaltUnsupportedAccess("PR31x00 RTC counter write", addr, value);

        case kOffAlarmHi:
            alarm_ = (static_cast<uint64_t>(value & 0xFFu) << 32) | (alarm_ & 0xFFFFFFFFull);
            alarm_armed_ = true;
            alarm_fired_ = false;
            NotifyWorker();
            return;

        case kOffAlarmLow:
            alarm_ = (alarm_ & ~0xFFFFFFFFull) | value;
            alarm_armed_ = true;
            alarm_fired_ = false;
            NotifyWorker();
            return;

        case kOffTimerCtl: {
            if (value & kTimerCtlReserved) {
                HaltUnsupportedAccess("PR31x00 RTC TimerCtl reserved bits 31-8", addr, value);
            }
            /* FREEZEPRE/FREEZERTC/FREEZETIMER stop counters mid-flight, ENPERTIMER
               starts the Periodic Timer, and TESTC8MS/ENTESTCLK/ENRTCTST are IC-test
               paths the datasheet says software should never set (§15.4.3). */
            if (value & kTimerCtlUnmodeled) {
                HaltUnsupportedAccess("PR31x00 RTC TimerCtl", addr, value);
            }
            const bool was_clr = rtc_clr_;
            rtc_clr_ = (value & kRtcClr) != 0;
            if (was_clr && !rtc_clr_) {
                /* Released: the counter starts from zero (§15.4.3 RTCCLR). */
                base_ticks_     = 0;
                anchor_         = Clock::now();
                alarm_fired_    = false;
                rollover_fired_ = false;
            }
            const bool was_periodic = periodic_enabled_;
            periodic_enabled_ = (value & kEnPerTimer) != 0;
            /* PERVAL loads into the counter when the timer is enabled (§15.4.4). */
            if (periodic_enabled_ && !was_periodic) {
                periodic_next_ = Clock::now() + PeriodLocked();
            }
            timer_ctl_ = value;
            NotifyWorker();
            return;
        }

        case kOffPeriodic:
            /* PERCNT<31:16> is read-only (§15.4.4); the write sets PERVAL<15:0>. */
            perval_ = static_cast<uint16_t>(value & kPervalMask);
            return;

        default:
            HaltUnsupportedAccess("PR31x00 RTC WriteWord", addr, value);
    }
}

void Pr31x00Rtc::SaveState(StateWriter& w) {
    std::lock_guard<std::mutex> lk(mtx_);
    w.Write("count", CountLocked());
    w.Write("alarm", alarm_);
    w.Write("alarm_armed", alarm_armed_);
    w.Write("alarm_fired", alarm_fired_);
    w.Write("rollover_fired", rollover_fired_);
    w.Write("timer_ctl", timer_ctl_);
    w.Write("rtc_clr", rtc_clr_);
    w.Write("perval", perval_);
    w.Write("periodic_enabled", periodic_enabled_);
    uint64_t rem_ns = 0;
    if (periodic_enabled_) {
        const auto now = Clock::now();
        if (periodic_next_ > now) {
            rem_ns = std::chrono::duration_cast<std::chrono::nanoseconds>(
                         periodic_next_ - now).count();
        }
    }
    w.Write("rem_ns", rem_ns);
}

void Pr31x00Rtc::RestoreState(StateReader& r) {
    std::lock_guard<std::mutex> lk(mtx_);
    r.Read("count", base_ticks_);
    r.Read("alarm", alarm_);
    r.Read("alarm_armed", alarm_armed_);
    r.Read("alarm_fired", alarm_fired_);
    r.Read("rollover_fired", rollover_fired_);
    r.Read("timer_ctl", timer_ctl_);
    r.Read("rtc_clr", rtc_clr_);
    r.Read("perval", perval_);
    r.Read("periodic_enabled", periodic_enabled_);
    uint64_t rem_ns = 0;
    r.Read("rem_ns", rem_ns);
    anchor_ = Clock::now();
    periodic_next_ = Clock::now() +
        std::chrono::duration_cast<Clock::duration>(std::chrono::nanoseconds(rem_ns));
}

void Pr31x00Rtc::PostRestore() {
    {
        std::lock_guard<std::mutex> lk(mtx_);
        EvaluateLocked();
    }
    NotifyWorker();
}

REGISTER_SERVICE(Pr31x00Rtc);
