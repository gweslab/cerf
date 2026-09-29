#include "pr31x00_rtc.h"

#include "pr31x00_clock.h"
#include "pr31x00_intc.h"

#include "../../boards/board_context.h"
#include "pr31500_id.h"
#include "pr31700_id.h"
#include "../../core/cerf_emulator.h"
#include "../../core/fatal.h"
#include "../../host/guest_deep_sleep.h"
#include "../../peripherals/peripheral_dispatcher.h"
#include "../../state/state_stream.h"
#include "../guest_cpu_reset.h"

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
constexpr uint64_t kRtcClkHz = 32768u;
constexpr uint32_t kRippleStageBits = 8u;

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

/* Periodic Timer (§15.4.4 p15-7): PERCNT[15:0]<31:16> read-only, PERVAL[15:0]<15:0> R/W, loaded
   "when the counter is enabled or when the counter reaches a count of zero"; Interrupt Rate =
   (PERVAL + 1) / f_TIMERCLK. */
constexpr uint32_t kPervalMask = 0xFFFFu;

}  /* namespace */

bool Pr31x00Rtc::ShouldRegister() {
    auto* bd = emu_.TryGet<BoardContext>();
    if (!bd) return false;
    const std::string_view soc = bd->GetSocId();
    return soc == SocId::Pr31500 || soc == SocId::Pr31700;
}

void Pr31x00Rtc::OnReady() {
    intc_         = &emu_.Get<Pr31x00Intc>();
    cycle_clock_  = &emu_.Get<GuestCycleClock>();
    module_clock_ = &emu_.Get<Pr31x00Clock>();
    per_event_    = cycle_clock_->Add([this] {
        std::lock_guard<std::mutex> lk(mtx_);
        PerEvaluateLocked();
        PerArmLocked();
    });
    module_clock_->RegisterModuleClockListener([this] {
        std::lock_guard<std::mutex> lk(mtx_);
        PerEvaluateLocked();
        PerRetimeLocked();
        PerArmLocked();
    });
    /* Timer Control RESET column: every bit 0 (§15.4.3 p15-6). */
    emu_.Get<GuestCpuReset>().RegisterResetListener([this](ResetLineKind) {
        bool moved;
        {
            std::lock_guard<std::mutex> lk(mtx_);
            const bool was_clr = rtc_clr_;
            ApplyTimerCtlLocked(0u);
            moved = was_clr != rtc_clr_;
        }
        if (moved) NotifyCountListeners();
    });
    osc_.Attach(kRtcClkHz, 1u);
    anchor_tick_ = osc_.Now();
    seen_tick_   = anchor_tick_;
    rtc_event_   = cycle_clock_->Add([this] {
        std::lock_guard<std::mutex> lk(mtx_);
        RtcEvaluateLocked();
        RtcArmLocked();
    });
    cycle_clock_->RegisterRateListener([this] {
        {
            std::lock_guard<std::mutex> lk(mtx_);
            RtcEvaluateLocked();
            osc_.Rescale();
            RtcArmLocked();
        }
        NotifyCountListeners();
    });
    auto& sleep = emu_.Get<GuestDeepSleep>();
    sleep.RegisterParkClock([this] {
        std::lock_guard<std::mutex> lk(mtx_);
        RtcEvaluateLocked();
        RtcArmLocked();
    });
    sleep.RegisterParkWakeDue([this] { return RtcWakeDueNs(); });
    emu_.Get<PeripheralDispatcher>().Register(this);
    std::lock_guard<std::mutex> lk(mtx_);
    RtcArmLocked();
}

uint64_t Pr31x00Rtc::PerElapsedLocked() {
    if (!per_running_) return per_held_;
    return per_held_ + per_ctr_.TicksSince(cycle_clock_->Cycles());
}

uint32_t Pr31x00Rtc::PerCntLocked() {
    if (!periodic_enabled_) return perval_;
    const uint64_t elapsed = PerElapsedLocked();
    return elapsed >= per_loaded_ ? 0u : static_cast<uint32_t>(per_loaded_ - elapsed);
}

void Pr31x00Rtc::PerEvaluateLocked() {
    if (!periodic_enabled_) return;
    for (;;) {
        const uint64_t elapsed = PerElapsedLocked();
        if (!per_int_done_ && elapsed >= per_loaded_) {
            intc_->SetPending(kStatusSet, kPerInt);
            per_int_done_ = true;
        }
        if (elapsed < static_cast<uint64_t>(per_loaded_) + 1u) return;
        const uint64_t reload = per_ctr_.CycleOfTick(per_loaded_ + 1u - per_held_);
        per_ctr_.Anchor(reload, 0u);
        per_held_     = 0u;
        per_loaded_   = perval_;
        per_int_done_ = false;
    }
}

void Pr31x00Rtc::PerArmLocked() {
    if (!periodic_enabled_ || !per_running_) {
        cycle_clock_->Disarm(per_event_);
        return;
    }
    const uint64_t target = per_int_done_
                                ? static_cast<uint64_t>(per_loaded_) + 1u + perval_
                                : static_cast<uint64_t>(per_loaded_);
    cycle_clock_->Arm(per_event_, per_ctr_.CycleOfTick(target - per_held_));
}

void Pr31x00Rtc::SetPerRatio() {
    const GuestCycleClock::Rate cpu   = cycle_clock_->ClockRate();
    const GuestCycleClock::Rate timer = module_clock_->TimerClockRate();
    if (!per_ctr_.SetRatio(cpu.num * timer.den, cpu.den * timer.num)) {
        emu_.Get<Fatal>().Die("Pr31x00Rtc: the %llu/%llu Hz core against the %llu/%llu Hz TIMERCLK "
                              "overflows the counter scale",
                              static_cast<unsigned long long>(cpu.num),
                              static_cast<unsigned long long>(cpu.den),
                              static_cast<unsigned long long>(timer.num),
                              static_cast<unsigned long long>(timer.den));
    }
}

void Pr31x00Rtc::PerRetimeLocked() {
    const uint64_t now = cycle_clock_->Cycles();
    const bool     run = periodic_enabled_ && module_clock_->TimerClockRate().num != 0u;
    if (per_running_) {
        const uint64_t phase = per_ctr_.PhaseAt(now);
        const uint64_t den   = per_ctr_.PhaseDenominator();
        per_held_ += per_ctr_.TicksSince(now);
        if (run) {
            SetPerRatio();
            if (!per_ctr_.AnchorAtPhase(now, 0u, phase, den)) {
                emu_.Get<Fatal>().Die("Pr31x00Rtc: the TIMERCLK phase %llu/%llu does not fit the "
                                      "new core ratio", static_cast<unsigned long long>(phase),
                                      static_cast<unsigned long long>(den));
            }
        }
    } else if (run) {
        SetPerRatio();
        per_ctr_.Anchor(now, 0u);
    }
    per_running_ = run;
}

/* §15.2.2 p15-3: the first ripple stage counts each C32K clock; RTCCLR holds all 40 bits at
   $0000000000 until it is cleared (§15.4.3 p15-6). */
uint64_t Pr31x00Rtc::CountAtTickLocked(uint64_t tick) const {
    if (rtc_clr_) return 0u;
    return (count_base_ + (tick - anchor_tick_)) & kMask40;
}

/* Figure 15.2.1 p15-2: TC0 of the first 8-bit ripple counter carries into the second. */
uint64_t Pr31x00Rtc::Tc0CarriesAtTickLocked(uint64_t tick) const {
    if (rtc_clr_) return carries_base_;
    return carries_base_ + ((count_base_ + (tick - anchor_tick_)) >> kRippleStageBits) -
           (count_base_ >> kRippleStageBits);
}

/* Figure 15.2.1 p15-2: the 40-bit equality comparator and the TC0-TC4 AND clock the ALARMINT and
   RTCINT flip-flops. */
uint64_t Pr31x00Rtc::NextRiseTickLocked(uint64_t tick, uint64_t value) const {
    const uint64_t ahead = (value - CountAtTickLocked(tick)) & kMask40;
    return tick + (ahead != 0u ? ahead : kMask40 + 1u);
}

uint32_t Pr31x00Rtc::RtcRisesLocked(uint64_t from, uint64_t to) const {
    if (rtc_clr_ || to <= from) return 0u;
    uint32_t bits = 0u;
    if (alarm_armed_ && NextRiseTickLocked(from, alarm_) <= to) bits |= kAlarmInt;
    if (NextRiseTickLocked(from, kMask40) <= to) bits |= kRtcInt;
    return bits;
}

void Pr31x00Rtc::RtcEvaluateLocked() {
    const uint64_t now  = osc_.Now();
    const uint32_t bits = RtcRisesLocked(seen_tick_, now);
    if (bits != 0u) intc_->SetPending(kStatusSet, bits);
    seen_tick_ = now;
}

void Pr31x00Rtc::RtcArmLocked() {
    if (rtc_clr_) {
        cycle_clock_->Disarm(rtc_event_);
        return;
    }
    uint64_t next = NextRiseTickLocked(seen_tick_, kMask40);
    if (alarm_armed_) next = std::min(next, NextRiseTickLocked(seen_tick_, alarm_));
    osc_.ArmAt(rtc_event_, next);
}

void Pr31x00Rtc::SetAlarmLocked(uint64_t alarm) {
    RtcEvaluateLocked();
    const uint64_t count     = CountAtTickLocked(seen_tick_);
    const bool     was_equal = alarm_armed_ && count == alarm_;
    alarm_       = alarm;
    alarm_armed_ = true;
    if (!was_equal && count == alarm_) intc_->SetPending(kStatusSet, kAlarmInt);
    RtcArmLocked();
}

void Pr31x00Rtc::SetRtcClrLocked(bool clr) {
    if (clr == rtc_clr_) return;
    RtcEvaluateLocked();
    if (clr) {
        const bool was_equal = alarm_armed_ && CountAtTickLocked(seen_tick_) == alarm_;
        carries_base_ = Tc0CarriesAtTickLocked(seen_tick_);
        rtc_clr_ = true;
        if (!was_equal && alarm_armed_ && alarm_ == 0u) intc_->SetPending(kStatusSet, kAlarmInt);
    } else {
        rtc_clr_     = false;
        count_base_  = 0u;
        anchor_tick_ = seen_tick_;
    }
    RtcArmLocked();
}

int64_t Pr31x00Rtc::RtcWakeDueNs() {
    std::lock_guard<std::mutex> lk(mtx_);
    RtcEvaluateLocked();
    int64_t due = GuestDeepSleep::kNoParkWake;
    if (rtc_clr_) return due;
    if (alarm_armed_ && intc_->WouldRaiseIrq(kStatusSet, kAlarmInt)) {
        due = std::min(due, osc_.SleptNsAtTick(NextRiseTickLocked(seen_tick_, alarm_)));
    }
    if (intc_->WouldRaiseIrq(kStatusSet, kRtcInt)) {
        due = std::min(due, osc_.SleptNsAtTick(NextRiseTickLocked(seen_tick_, kMask40)));
    }
    return due;
}

uint64_t Pr31x00Rtc::Count() {
    std::lock_guard<std::mutex> lk(mtx_);
    RtcEvaluateLocked();
    return CountAtTickLocked(seen_tick_);
}

uint64_t Pr31x00Rtc::Tc0Carries() {
    std::lock_guard<std::mutex> lk(mtx_);
    RtcEvaluateLocked();
    return Tc0CarriesAtTickLocked(seen_tick_);
}

std::optional<uint64_t> Pr31x00Rtc::CycleOfTc0Carry(uint64_t n) {
    std::lock_guard<std::mutex> lk(mtx_);
    RtcEvaluateLocked();
    if (rtc_clr_) return std::nullopt;
    const uint64_t done = Tc0CarriesAtTickLocked(seen_tick_);
    if (n <= done) {
        emu_.Get<Fatal>().Die("Pr31x00Rtc: TC0 carry %llu asked for at carry %llu",
                              static_cast<unsigned long long>(n),
                              static_cast<unsigned long long>(done));
    }
    const uint64_t stage = count_base_ >> kRippleStageBits;
    const uint64_t more  = n - carries_base_;
    if (more > (UINT64_MAX >> kRippleStageBits) - stage) {
        emu_.Get<Fatal>().Die("Pr31x00Rtc: TC0 carry %llu overflows the crystal tick count",
                              static_cast<unsigned long long>(n));
    }
    const uint64_t ahead = ((stage + more) << kRippleStageBits) - count_base_;
    if (ahead > UINT64_MAX - anchor_tick_) {
        emu_.Get<Fatal>().Die("Pr31x00Rtc: TC0 carry %llu overflows the crystal tick count",
                              static_cast<unsigned long long>(n));
    }
    return osc_.CycleOf(anchor_tick_ + ahead);
}

void Pr31x00Rtc::RegisterCountListener(std::function<void()> fn) {
    count_listeners_.push_back(std::move(fn));
}

void Pr31x00Rtc::NotifyCountListeners() {
    for (auto& fn : count_listeners_) fn();
}

void Pr31x00Rtc::ApplyTimerCtlLocked(uint32_t value) {
    SetRtcClrLocked((value & kRtcClr) != 0u);
    PerEvaluateLocked();
    const bool was_periodic = periodic_enabled_;
    periodic_enabled_ = (value & kEnPerTimer) != 0;
    if (periodic_enabled_ && !was_periodic) {
        per_loaded_   = perval_;
        per_held_     = 0u;
        per_int_done_ = false;
        per_running_  = false;
    }
    PerRetimeLocked();
    PerArmLocked();
    timer_ctl_ = value;
}

uint32_t Pr31x00Rtc::ReadWord(uint32_t addr) {
    std::lock_guard<std::mutex> lk(mtx_);
    const uint32_t off = addr - kBase;
    switch (off) {
        case kOffRtcHi:
            RtcEvaluateLocked();
            return static_cast<uint32_t>(CountAtTickLocked(seen_tick_) >> 32);
        case kOffRtcLow:
            RtcEvaluateLocked();
            return static_cast<uint32_t>(CountAtTickLocked(seen_tick_) & 0xFFFFFFFFu);
        case kOffAlarmHi:  return static_cast<uint32_t>(alarm_ >> 32);
        case kOffAlarmLow: return static_cast<uint32_t>(alarm_ & 0xFFFFFFFFu);
        case kOffTimerCtl: return timer_ctl_;
        case kOffPeriodic:
            PerEvaluateLocked();
            PerArmLocked();
            return (PerCntLocked() << 16) | perval_;
        default:           HaltUnsupportedAccess("PR31x00 RTC ReadWord", addr, 0);
    }
}

void Pr31x00Rtc::WriteWord(uint32_t addr, uint32_t value) {
    std::unique_lock<std::mutex> lk(mtx_);
    const uint32_t off = addr - kBase;
    switch (off) {
        case kOffRtcHi:
        case kOffRtcLow:
            /* The RTC counter is read-only (§15.4.1). */
            HaltUnsupportedAccess("PR31x00 RTC counter write", addr, value);

        case kOffAlarmHi:
            SetAlarmLocked((static_cast<uint64_t>(value & 0xFFu) << 32) | (alarm_ & 0xFFFFFFFFull));
            return;

        case kOffAlarmLow:
            SetAlarmLocked((alarm_ & ~0xFFFFFFFFull) | value);
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
            ApplyTimerCtlLocked(value);
            const bool moved = was_clr != rtc_clr_;
            lk.unlock();
            if (moved) NotifyCountListeners();
            return;
        }

        case kOffPeriodic:
            /* PERCNT<31:16> is read-only (§15.4.4); the write sets PERVAL<15:0>. */
            PerEvaluateLocked();
            perval_ = static_cast<uint16_t>(value & kPervalMask);
            PerArmLocked();
            return;

        default:
            HaltUnsupportedAccess("PR31x00 RTC WriteWord", addr, value);
    }
}

void Pr31x00Rtc::SaveState(StateWriter& w) {
    std::lock_guard<std::mutex> lk(mtx_);
    osc_.Save(w);
    const uint64_t now = osc_.Now();
    w.Write("count", CountAtTickLocked(now));
    w.Write("tc0_carries", Tc0CarriesAtTickLocked(now));
    w.Write("rtc_rises", RtcRisesLocked(seen_tick_, now));
    w.Write("alarm", alarm_);
    w.Write("alarm_armed", alarm_armed_);
    w.Write("timer_ctl", timer_ctl_);
    w.Write("rtc_clr", rtc_clr_);
    w.Write("perval", perval_);
    w.Write("periodic_enabled", periodic_enabled_);
    w.Write("per_loaded", per_loaded_);
    w.Write("per_elapsed", PerElapsedLocked());
    w.Write("per_int_done", per_int_done_);
}

void Pr31x00Rtc::RestoreState(StateReader& r) {
    std::lock_guard<std::mutex> lk(mtx_);
    osc_.Restore(r);
    r.Read("count", count_base_);
    r.Read("tc0_carries", carries_base_);
    r.Read("rtc_rises", rises_pending_);
    r.Read("alarm", alarm_);
    r.Read("alarm_armed", alarm_armed_);
    r.Read("timer_ctl", timer_ctl_);
    r.Read("rtc_clr", rtc_clr_);
    r.Read("perval", perval_);
    r.Read("periodic_enabled", periodic_enabled_);
    r.Read("per_loaded", per_loaded_);
    r.Read("per_elapsed", per_held_);
    r.Read("per_int_done", per_int_done_);
    per_running_ = false;
    anchor_tick_ = osc_.Now();
    seen_tick_   = anchor_tick_;
}

void Pr31x00Rtc::PostRestore() {
    {
        std::lock_guard<std::mutex> lk(mtx_);
        if (rises_pending_ != 0u) intc_->SetPending(kStatusSet, rises_pending_);
        rises_pending_ = 0u;
        RtcEvaluateLocked();
        RtcArmLocked();
        PerRetimeLocked();
        PerEvaluateLocked();
        PerArmLocked();
    }
    NotifyCountListeners();
}

REGISTER_SERVICE(Pr31x00Rtc);
