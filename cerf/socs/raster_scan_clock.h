#pragma once

#include "../jit/guest_cycle_clock.h"
#include "rated_tick_count.h"

#include <cstdint>

class RasterScanClock {
public:
    static constexpr uint32_t kMaxEdges = 2u;

    struct Frame {
        uint64_t ticks = 1;
        uint64_t edge[kMaxEdges] = {};
        uint32_t edges = 0;
    };

    using Position = RatedTickCount::Position;

    bool Start(uint64_t cycle, GuestCycleClock::Rate core, GuestCycleClock::Rate tick,
               const Frame& frame);
    bool Resume(uint64_t cycle, GuestCycleClock::Rate core, GuestCycleClock::Rate tick,
                const Frame& frame, const Position& at);
    bool Rescale(uint64_t cycle, GuestCycleClock::Rate core, GuestCycleClock::Rate tick);

    Position PositionAt(uint64_t cycle) const { return ticks_.PositionAt(cycle); }
    uint64_t TickInFrame(uint64_t cycle) const;
    bool     EdgeCycle(uint64_t edge, uint64_t& cycle) const;
    uint32_t EdgesPerFrame() const { return frame_.edges; }

private:
    static bool FrameValid(const Frame& frame);
    bool        SetFrame(const Frame& frame);

    RatedTickCount ticks_;
    Frame          frame_;
};
