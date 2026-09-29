#pragma once

#include "../jit/guest_cycle_clock.h"
#include "cycle_anchored_counter.h"

#include <cstdint>

class RatedTickCount {
public:
    struct Position {
        uint64_t ticks     = 0;
        uint64_t phase     = 0;
        uint64_t phase_den = 1;
    };

    bool SetRate(GuestCycleClock::Rate core, GuestCycleClock::Rate tick);
    void Start(uint64_t cycle);
    bool PlaceAt(uint64_t cycle, const Position& at);
    bool Rescale(uint64_t cycle, GuestCycleClock::Rate core, GuestCycleClock::Rate tick);
    bool AddTicks(uint64_t ticks);

    Position PositionAt(uint64_t cycle) const;

    uint64_t TicksAt(uint64_t cycle) const { return base_ + ctr_.TicksSince(cycle); }

    uint64_t CycleOfTick(uint64_t tick) const {
        return ctr_.CycleOfTick(tick > base_ ? tick - base_ : 0u);
    }

private:
    CycleAnchoredCounter ctr_;
    uint64_t             base_ = 0;
};
