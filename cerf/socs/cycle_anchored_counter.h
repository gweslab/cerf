#pragma once

#include "../core/tick_scale.h"

#include <cstdint>

class CycleAnchoredCounter {
public:
    bool SetRatio(uint64_t cycles, uint64_t ticks);
    bool Rescale(uint64_t cycle, uint64_t cycles, uint64_t ticks);
    bool AnchorAtPhase(uint64_t cycle, uint32_t count, uint64_t phase, uint64_t denominator);

    void Anchor(uint64_t cycle, uint32_t count) {
        anchor_cycle_ = cycle;
        anchor_count_ = count;
    }

    void SetCountAt(uint64_t cycle, uint32_t count) {
        anchor_count_ = count - static_cast<uint32_t>(TicksSince(cycle));
    }

    uint64_t PhaseAt(uint64_t cycle) const {
        return ((cycle - anchor_cycle_) % cyc_unit_) * tk_unit_ % cyc_unit_;
    }

    uint64_t PhaseDenominator() const { return cyc_unit_; }

    uint64_t AnchorCycle() const { return anchor_cycle_; }
    uint32_t AnchorCount() const { return anchor_count_; }

    uint64_t TicksSince(uint64_t cycle) const {
        return ScaleU64(cycle - anchor_cycle_, tk_unit_, cyc_unit_);
    }

    uint32_t CountAt(uint64_t cycle) const {
        return anchor_count_ + static_cast<uint32_t>(TicksSince(cycle));
    }

    uint64_t CycleOfTick(uint64_t ticks_after_anchor) const {
        return anchor_cycle_ + ScaleU64Ceil(ticks_after_anchor, cyc_unit_, tk_unit_);
    }

    uint64_t NextMatchCycle(uint32_t match, uint64_t cycle) const {
        const uint64_t since = TicksSince(cycle);
        const uint32_t d     = match - (anchor_count_ + static_cast<uint32_t>(since));
        return CycleOfTick(since + (d != 0u ? d : kCounterWrapTicks));
    }

private:
    static constexpr uint64_t kCounterWrapTicks = 0x100000000ull;

    static bool ReduceRatio(uint64_t cycles, uint64_t ticks, uint64_t& cyc, uint64_t& tk);

    void PlaceAnchor(uint64_t cycle, uint32_t count, uint64_t phase, uint64_t denominator);

    uint32_t anchor_count_ = 0;
    uint64_t anchor_cycle_ = 0;
    uint64_t cyc_unit_     = 1;
    uint64_t tk_unit_      = 1;
};
