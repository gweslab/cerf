#pragma once

#include <cstdint>
#include <functional>
#include <memory>
#include <vector>

#include "../core/service.h"

#if CERF_DEV_MODE
#include <atomic>
#endif

class VirtualClock;

class GuestCycleClock : public Service {
public:
    using Service::Service;
    ~GuestCycleClock() override;

    class Event {
    public:
        explicit Event(std::function<void()> fn) : fn_(std::move(fn)) {}

    private:
        friend class GuestCycleClock;
        std::function<void()> fn_;
        uint64_t              at_    = 0;
        bool                  armed_ = false;
    };

    void OnReady() override;

    Event* Add(std::function<void()> fn);
    void   Arm(Event* e, uint64_t at_cycle);
    void   Disarm(Event* e);
    bool   IsDue(const Event* e, uint64_t now) const;

    uint64_t Cycles() { return CyclesNow(); }
    uint64_t CpuHz() const { return cpu_hz_; }
    void     SetClockHz(uint64_t hz);
    void     RegisterRateListener(std::function<void()> fn);
    int64_t  NowNs() { return CyclesToNs(CyclesNow()); }
    uint64_t NsToCycles(int64_t ns) const;
    int64_t  CyclesToNs(uint64_t cycles) const;

    void OnDispatch();
    void IdleStep(void* wake_event);
    void OnCyclesRestored();

#if CERF_DEV_MODE
    int64_t LagNsAtLastSecond() const {
        return stat_lag_published_ns_.load(std::memory_order_relaxed);
    }
#endif

protected:
    virtual uint32_t ClockHz()                          = 0;
    virtual uint64_t CyclesNow()                        = 0;
    virtual void     SetCycles(uint64_t cycles)         = 0;
    virtual void     PublishDeadline(uint64_t cycles_ahead) = 0;

private:
    void     SetUnits(uint64_t hz);
    void     RunDue(uint64_t now);
    uint64_t NextArmed() const;
    void     Publish(uint64_t now);
    void     OnThrottle();
    int64_t  TargetWallNs(uint64_t cycle) const;
    void     SleepUntilWallNs(int64_t target_ns);
    void     ArmWaitTimer(int64_t ns);

    std::vector<std::unique_ptr<Event>> events_;
    std::vector<std::function<void()>>  rate_listeners_;
    Event*        throttle_    = nullptr;
    VirtualClock* wall_        = nullptr;
    void*         timer_       = nullptr;
    uint64_t      cpu_hz_      = 1;
    uint64_t      ns_unit_     = 1;
    uint64_t      cyc_unit_    = 1;
    uint64_t      ref_cycle_   = 0;
    int64_t       ref_wall_ns_ = 0;

#if CERF_DEV_MODE
    void LogSecond();
    uint32_t stat_throttles_    = 0;
    uint32_t stat_sleeps_       = 0;
    int64_t  stat_sleep_ns_     = 0;
    int64_t  stat_wake_over_ns_ = 0;
    int64_t  stat_stall_ns_     = 0;
    int64_t  stat_prev_lag_ns_  = 0;
    int64_t  stat_forgiven_ns_  = 0;
    uint32_t stat_idle_steps_   = 0;
    uint32_t stat_idle_early_   = 0;
    int64_t  stat_idle_wait_ns_ = 0;
    int64_t  stat_wall_mark_ns_ = 0;
    uint64_t stat_cycle_mark_   = 0;
    std::atomic<int64_t> stat_lag_published_ns_{0};
#endif
};
