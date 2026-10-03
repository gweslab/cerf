#pragma once

#include "../../core/service.h"
#include "../../jit/guest_cycle_clock.h"
#include "../rated_tick_count.h"

#include <cstdint>
#include <functional>

class GuestCpuReset;
class Sa11xxGpio;
class Sa11xxSspClockInput;
class StateReader;
class StateWriter;

class Sa11xxSspBitClock : public Service {
public:
    using BeforeChange = std::function<void(uint64_t now, bool stops)>;
    using AfterChange  = std::function<void(uint64_t now)>;

    using Service::Service;

    bool ShouldRegister() override;
    void OnReady() override;

    void SetListener(BeforeChange before, AfterChange after);
    void Start(uint64_t now, uint32_t sscr0, uint32_t sscr1);
    void Change(uint64_t now, uint32_t sscr0, uint32_t sscr1);
    void Stop() { started_ = false; clocked_ = false; }

    bool                  Clocked() const { return clocked_; }
    GuestCycleClock::Rate BitRate() const { return rate_; }
    uint64_t TicksAt(uint64_t now) const { return bits_.TicksAt(now); }
    uint64_t CycleOfTick(uint64_t tick) const { return bits_.CycleOfTick(tick); }

    void Save(StateWriter& w);
    void Restore(StateReader& r);

private:
    bool Select(uint32_t sscr0, uint32_t sscr1, GuestCycleClock::Rate& rate) const;
    void Reevaluate();
    void OnCpuRate();
    void RequireRatio(bool fits) const;

    GuestCycleClock*     clock_ = nullptr;
    Sa11xxGpio*          gpio_  = nullptr;
    Sa11xxSspClockInput* input_ = nullptr;
    GuestCpuReset*       reset_ = nullptr;
    BeforeChange         before_;
    AfterChange          after_;
    RatedTickCount           bits_;
    RatedTickCount::Position held_{};
    GuestCycleClock::Rate    rate_{};
    uint32_t sscr0_   = 0;
    uint32_t sscr1_   = 0;
    bool     started_ = false;
    bool     clocked_ = false;
};
