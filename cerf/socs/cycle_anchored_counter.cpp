#include "cycle_anchored_counter.h"

#include <numeric>

bool CycleAnchoredCounter::ReduceRatio(uint64_t cycles, uint64_t ticks, uint64_t& cyc,
                                       uint64_t& tk) {
    const uint64_t g = std::gcd(cycles, ticks);
    cyc = cycles / g;
    tk  = ticks / g;
    return (cyc - 1u) <= UINT64_MAX / tk && (tk - 1u) <= (UINT64_MAX - tk) / cyc;
}

bool CycleAnchoredCounter::SetRatio(uint64_t cycles, uint64_t ticks) {
    uint64_t cyc = 0, tk = 0;
    if (!ReduceRatio(cycles, ticks, cyc, tk)) return false;
    cyc_unit_ = cyc;
    tk_unit_  = tk;
    return true;
}

bool CycleAnchoredCounter::Rescale(uint64_t cycle, uint64_t cycles, uint64_t ticks) {
    uint64_t cyc = 0, tk = 0;
    if (!ReduceRatio(cycles, ticks, cyc, tk)) return false;
    const uint64_t part  = PhaseAt(cycle);
    const uint64_t den   = cyc_unit_;
    const uint32_t count = CountAt(cycle);
    if (part != 0u && part > UINT64_MAX / cyc) return false;
    cyc_unit_ = cyc;
    tk_unit_  = tk;
    PlaceAnchor(cycle, count, part, den);
    return true;
}

bool CycleAnchoredCounter::AnchorAtPhase(uint64_t cycle, uint32_t count, uint64_t phase,
                                         uint64_t denominator) {
    if (denominator == 0u || phase >= denominator) return false;
    if (phase != 0u && phase > UINT64_MAX / cyc_unit_) return false;
    PlaceAnchor(cycle, count, phase, denominator);
    return true;
}

void CycleAnchoredCounter::PlaceAnchor(uint64_t cycle, uint32_t count, uint64_t phase,
                                       uint64_t denominator) {
    anchor_count_ = count;
    anchor_cycle_ = cycle - phase * cyc_unit_ / denominator / tk_unit_;
}
