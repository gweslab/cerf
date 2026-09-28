#pragma once

#include "../jit/guest_cycle_clock.h"
#include "cycle_anchored_counter.h"

#include <cstdint>

class CerfEmulator;
class GuestDeepSleep;
class StateReader;
class StateWriter;

class OscillatorTicks {
public:
    OscillatorTicks(CerfEmulator& emu, bool credits_park) : emu_(emu), credits_park_(credits_park) {}
    virtual ~OscillatorTicks() = default;

    struct Reading {
        uint64_t total;
        uint64_t park;
    };

    void     Attach(uint64_t osc_num, uint64_t osc_den);
    uint64_t Now();
    Reading  Sample();
    uint64_t CycleOf(uint64_t tick);
    void     ArmAt(GuestCycleClock::Event* event, uint64_t tick);
    int64_t  SleptNsAtTick(uint64_t tick);
    void     SetOscRate(uint64_t osc_num, uint64_t osc_den);
    void     Rescale();
    void     Rebase();
    void     CreditAwakeNs(uint64_t ns);

    GuestCycleClock::Rate OscRate() const { return GuestCycleClock::Rate{osc_num_, osc_den_}; }

    void Save(StateWriter& w);
    void Restore(StateReader& r);

protected:
    virtual uint64_t ClockCycles();
    virtual bool     ClockStopped() { return false; }

    CerfEmulator&    emu_;
    GuestCycleClock* clock_ = nullptr;
    GuestDeepSleep*  sleep_ = nullptr;

private:
    uint64_t Scale() const;
    bool     SetRatio();
    void     RequireRatio();
    void     RescaleAt(uint64_t now);
    void     DrainPark();
    uint64_t CreditNs(uint64_t ns);

    const bool           credits_park_;
    CycleAnchoredCounter ctr_;
    uint64_t             osc_num_    = 1;
    uint64_t             osc_den_    = 1;
    uint64_t             base_       = 0;
    uint64_t             park_ticks_ = 0;
    uint64_t             credit_rem_ = 0;
    int64_t              slept_seen_ = 0;
};
