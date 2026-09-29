#include "rated_tick_count.h"

bool RatedTickCount::SetRate(GuestCycleClock::Rate core, GuestCycleClock::Rate tick) {
    if (core.num == 0u || core.den == 0u || tick.num == 0u || tick.den == 0u ||
        core.num > UINT64_MAX / tick.den || core.den > UINT64_MAX / tick.num) {
        return false;
    }
    return ctr_.SetRatio(core.num * tick.den, core.den * tick.num);
}

void RatedTickCount::Start(uint64_t cycle) {
    ctr_.Anchor(cycle, 0u);
    base_ = 0u;
}

bool RatedTickCount::PlaceAt(uint64_t cycle, const Position& at) {
    if (!ctr_.AnchorAtPhase(cycle, 0u, at.phase, at.phase_den)) return false;
    base_ = at.ticks;
    return true;
}

bool RatedTickCount::Rescale(uint64_t cycle, GuestCycleClock::Rate core,
                             GuestCycleClock::Rate tick) {
    const Position at = PositionAt(cycle);
    if (!SetRate(core, tick)) return false;
    return PlaceAt(cycle, at);
}

bool RatedTickCount::AddTicks(uint64_t ticks) {
    if (ticks > UINT64_MAX - base_) return false;
    base_ += ticks;
    return true;
}

RatedTickCount::Position RatedTickCount::PositionAt(uint64_t cycle) const {
    Position p;
    p.ticks     = TicksAt(cycle);
    p.phase     = ctr_.PhaseAt(cycle);
    p.phase_den = ctr_.PhaseDenominator();
    return p;
}
