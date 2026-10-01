#include "guest_cycle_clock.h"

#include "../core/cerf_emulator.h"
#include "../core/fatal.h"
#include "../core/tick_scale.h"
#include "../core/virtual_clock.h"

#if CERF_DEV_MODE
#include "../core/log.h"
#endif

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>

#include <algorithm>
#include <numeric>

namespace {

constexpr uint64_t kNsPerSec        = 1000000000ull;
constexpr int64_t  kThrottleSliceNs = 1000000;
constexpr int64_t  kMaxCatchUpNs    = 100000000;
constexpr uint64_t kNever           = UINT64_MAX;

}

GuestCycleClock::~GuestCycleClock() {
    if (timer_ != nullptr) CloseHandle(timer_);
}

GuestCycleClock::Rate GuestCycleClock::Normalized(Rate rate) const {
    if (rate.num == 0u || rate.den == 0u || rate.den > UINT64_MAX / kNsPerSec) {
        emu_.Get<Fatal>().Die("GuestCycleClock: the clock rate %llu/%llu Hz",
                              static_cast<unsigned long long>(rate.num),
                              static_cast<unsigned long long>(rate.den));
    }
    const uint64_t g = std::gcd(rate.num, rate.den);
    return Rate{rate.num / g, rate.den / g};
}

uint64_t GuestCycleClock::CpuHz() const {
    if (rate_.den != 1u) {
        emu_.Get<Fatal>().Die("GuestCycleClock: an integral Hz read of the rate %llu/%llu Hz",
                              static_cast<unsigned long long>(rate_.num),
                              static_cast<unsigned long long>(rate_.den));
    }
    return rate_.num;
}

void GuestCycleClock::SetUnits(Rate rate) {
    rate_ = rate;
    const uint64_t ns = kNsPerSec * rate_.den;
    const uint64_t g  = std::gcd(ns, rate_.num);
    ns_unit_  = ns / g;
    cyc_unit_ = rate_.num / g;
}

void GuestCycleClock::SetClockRate(Rate rate) {
    const Rate     r       = Normalized(rate);
    const uint64_t request = ++rate_requests_;
    if (r.num == rate_.num && r.den == rate_.den) return;
    const uint64_t now = CyclesNow();
    RunDue(now);
    if (rate_requests_ != request) return;
    const int64_t slice_left_ns =
        throttle_->armed_ ? CyclesToNs(throttle_->at_ - now) : kThrottleSliceNs;
    ref_wall_ns_ = TargetWallNs(now);
    ref_cycle_   = now;
    guest_ns_      += CyclesToNs(now - guest_ns_cycle_);
    guest_ns_cycle_ = now;
    SetUnits(r);
    Arm(throttle_, now + NsToCycles(slice_left_ns));
    for (auto& fn : rate_listeners_) fn();
}

void GuestCycleClock::RegisterRateListener(std::function<void()> fn) {
    rate_listeners_.push_back(std::move(fn));
}

void GuestCycleClock::RegisterIdleListener(std::function<void()> fn) {
    idle_listeners_.push_back(std::move(fn));
}

void GuestCycleClock::RegisterIdleExitListener(std::function<void()> fn) {
    idle_exit_listeners_.push_back(std::move(fn));
}

void GuestCycleClock::ExitIdle() {
    if (!in_idle_) return;
    in_idle_ = false;
    for (auto& fn : idle_exit_listeners_) fn();
}

void GuestCycleClock::OnReady() {
    SetUnits(Normalized(InitialRate()));
    wall_ = &emu_.Get<VirtualClock>();
    timer_ = CreateWaitableTimerExW(nullptr, nullptr,
                                    CREATE_WAITABLE_TIMER_HIGH_RESOLUTION,
                                    TIMER_ALL_ACCESS);
    if (timer_ == nullptr) timer_ = CreateWaitableTimerW(nullptr, FALSE, nullptr);
    if (timer_ == nullptr) {
        emu_.Get<Fatal>().Die("GuestCycleClock: waitable timer creation failed gle=%lu",
                              GetLastError());
    }
    throttle_ = Add([this] { OnThrottle(); });
    OnCyclesRestored();
}

uint64_t GuestCycleClock::NsToCycles(int64_t ns) const {
    return ScaleU64(static_cast<uint64_t>(ns), cyc_unit_, ns_unit_);
}

int64_t GuestCycleClock::CyclesToNs(uint64_t cycles) const {
    return static_cast<int64_t>(ScaleU64(cycles, ns_unit_, cyc_unit_));
}

GuestCycleClock::Event* GuestCycleClock::Add(std::function<void()> fn) {
    events_.push_back(std::make_unique<Event>(std::move(fn)));
    return events_.back().get();
}

void GuestCycleClock::Arm(Event* e, uint64_t at_cycle) {
    e->at_    = at_cycle;
    e->armed_ = true;
    Publish(CyclesNow());
}

void GuestCycleClock::Disarm(Event* e) {
    e->armed_ = false;
    Publish(CyclesNow());
}

bool GuestCycleClock::IsDue(const Event* e, uint64_t now) const {
    return e->armed_ && e->at_ <= now;
}

uint64_t GuestCycleClock::NextArmed() const {
    uint64_t next = kNever;
    for (const auto& e : events_) {
        if (e->armed_ && e->at_ < next) next = e->at_;
    }
    return next;
}

void GuestCycleClock::Publish(uint64_t now) {
    const uint64_t next = NextArmed();
    PublishDeadline(next > now ? next - now : 0u);
}

void GuestCycleClock::RunDue(uint64_t now) {
    for (;;) {
        Event* due = nullptr;
        for (const auto& e : events_) {
            if (e->armed_ && e->at_ <= now && (due == nullptr || e->at_ < due->at_)) {
                due = e.get();
            }
        }
        if (due == nullptr) return;
        due->armed_ = false;
        due->fn_();
    }
}

void GuestCycleClock::OnDispatch() {
    const uint64_t now = CyclesNow();
    RunDue(now);
    Publish(now);
}

int64_t GuestCycleClock::TargetWallNs(uint64_t cycle) const {
    return ref_wall_ns_ + CyclesToNs(cycle - ref_cycle_);
}

void GuestCycleClock::ArmWaitTimer(int64_t ns) {
    LARGE_INTEGER due;
    due.QuadPart = -((ns + 99) / 100);
    SetWaitableTimer(timer_, &due, 0, nullptr, nullptr, FALSE);
}

void GuestCycleClock::SleepUntilWallNs(int64_t target_ns) {
    for (;;) {
        const int64_t remaining = target_ns - wall_->NowNs();
        if (remaining <= 0) return;
        ArmWaitTimer(remaining);
        WaitForSingleObject(timer_, INFINITE);
    }
}

void GuestCycleClock::OnThrottle() {
    const uint64_t now    = CyclesNow();
    const int64_t  target = TargetWallNs(now);
    const int64_t  wall   = wall_->NowNs();
    if (target > wall) {
        SleepUntilWallNs(target);
#if CERF_DEV_MODE
        ++stat_sleeps_;
        stat_sleep_ns_ += target - wall;
        stat_wake_over_ns_ += wall_->NowNs() - target;
        stat_prev_lag_ns_ = 0;
#endif
    } else {
#if CERF_DEV_MODE
        const int64_t grown = (wall - target) - stat_prev_lag_ns_;
        if (grown > 0) stat_stall_ns_ += grown;
#endif
        if (wall - target > kMaxCatchUpNs) {
            ref_wall_ns_ += (wall - target) - kMaxCatchUpNs;
#if CERF_DEV_MODE
            stat_forgiven_ns_ += (wall - target) - kMaxCatchUpNs;
#endif
        }
#if CERF_DEV_MODE
        stat_prev_lag_ns_ = std::min<int64_t>(wall - target, kMaxCatchUpNs);
#endif
    }
#if CERF_DEV_MODE
    if (++stat_throttles_ % 1000u == 0u) LogSecond();
#endif
    Arm(throttle_, now + NsToCycles(kThrottleSliceNs));
}

void GuestCycleClock::IdleStep(void* wake_event) {
    in_idle_ = true;
    for (auto& fn : idle_listeners_) fn();
    const uint64_t now  = CyclesNow();
    const uint64_t next = NextArmed();
    if (next == kNever) {
        emu_.Get<Fatal>().Die("GuestCycleClock: idle with no armed event");
    }
    if (next <= now) {
        RunDue(now);
        Publish(now);
        return;
    }
    const int64_t target = TargetWallNs(next);
    int64_t        wall   = wall_->NowNs();
    if (target > wall) {
        ArmWaitTimer(target - wall);
        HANDLE objs[2] = { static_cast<HANDLE>(wake_event), timer_ };
        WaitForMultipleObjects(2, objs, FALSE, INFINITE);
        CancelWaitableTimer(timer_);
#if CERF_DEV_MODE
        stat_idle_wait_ns_ += target - wall;
#endif
        wall = wall_->NowNs();
    }
    uint64_t advanced = next;
    if (wall < target) {
        const int64_t elapsed = wall - TargetWallNs(now);
        advanced = elapsed > 0 ? std::min(next, now + NsToCycles(elapsed)) : now;
#if CERF_DEV_MODE
        ++stat_idle_early_;
#endif
    }
#if CERF_DEV_MODE
    ++stat_idle_steps_;
#endif
    SetCycles(advanced);
    RunDue(advanced);
    Publish(advanced);
}

#if CERF_DEV_MODE
void GuestCycleClock::LogSecond() {
    const uint64_t now      = CyclesNow();
    const int64_t  wall     = wall_->NowNs();
    const int64_t  guest_ns = NowNs();
    LOG(Jit, "[CYCLECLK] guest_s=%llu guest_ms=%lld wall_ms=%lld lag_ms=%lld | "
             "sleeps=%u sleep_ms=%lld wake_over_us=%lld stall_us=%lld "
             "forgiven_ms=%lld | idle_steps=%u early=%u idle_wait_ms=%lld\n",
        static_cast<unsigned long long>(stat_throttles_ / 1000u),
        static_cast<long long>((guest_ns - stat_guest_mark_ns_) / 1000000),
        static_cast<long long>((wall - stat_wall_mark_ns_) / 1000000),
        static_cast<long long>((wall - TargetWallNs(now)) / 1000000),
        stat_sleeps_, static_cast<long long>(stat_sleep_ns_ / 1000000),
        static_cast<long long>(stat_wake_over_ns_ / 1000),
        static_cast<long long>(stat_stall_ns_ / 1000),
        static_cast<long long>(stat_forgiven_ns_ / 1000000),
        stat_idle_steps_, stat_idle_early_,
        static_cast<long long>(stat_idle_wait_ns_ / 1000000));
    stat_sleeps_ = 0;  stat_sleep_ns_ = 0;  stat_forgiven_ns_ = 0;
    stat_wake_over_ns_ = 0;  stat_stall_ns_ = 0;
    stat_idle_steps_ = 0;  stat_idle_early_ = 0;  stat_idle_wait_ns_ = 0;
    stat_guest_mark_ns_ = guest_ns;
    stat_wall_mark_ns_  = wall;
    stat_lag_published_ns_.store(wall - TargetWallNs(now), std::memory_order_relaxed);
}
#endif

void GuestCycleClock::OnCyclesRestored() {
    ref_cycle_      = CyclesNow();
    ref_wall_ns_    = wall_->NowNs();
    guest_ns_cycle_ = ref_cycle_;
    guest_ns_       = CyclesToNs(ref_cycle_);
#if CERF_DEV_MODE
    stat_guest_mark_ns_ = guest_ns_;
    stat_wall_mark_ns_  = ref_wall_ns_;
#endif
    Arm(throttle_, ref_cycle_ + NsToCycles(kThrottleSliceNs));
}
