#pragma once

#include <cstdint>

namespace cerf_freescale_gpt_detail {

/* The GPTCNT sequence from a base value: MCIMX31RM 34.1.2 and Table 34-6 FRR,
   MCIMX51RM 36.1.3 and Table 36-5 FRR. */
class GptCountSequence {
public:
    GptCountSequence(uint32_t base, bool free_run, uint32_t ocr1)
        : base_(base), free_run_(free_run), ocr1_(ocr1) {}

    uint32_t ValueAt(uint64_t t) const {
        if (free_run_) return base_ + static_cast<uint32_t>(t);
        const uint64_t z = FirstZero();
        if (t < z) return base_ + static_cast<uint32_t>(t);
        return static_cast<uint32_t>((t - z) % Period());
    }

    /* MCIMX31RM Figure 34-17 / MCIMX51RM Figure 36-15: the compare flag sets on the counter
       edge that moves GPTCNT off the compare value. */
    bool NextCompare(uint32_t x, uint64_t after, uint64_t& at) const {
        uint64_t reach = 0u;
        if (free_run_) {
            reach = EarliestFrom(static_cast<uint32_t>(x - base_), kWrap, after);
        } else {
            const uint64_t z = FirstZero();
            if (x >= base_ && uint64_t{x} - base_ < z && uint64_t{x} - base_ >= after) {
                reach = uint64_t{x} - base_;
            } else if (uint64_t{x} < Period()) {
                reach = EarliestFrom(z + x, Period(), after);
            } else {
                return false;
            }
        }
        at = reach + 1u;
        return true;
    }

    /* MCIMX31RM Table 34-8 / MCIMX51RM Table 36-7 ROV: set when the counter
       reaches 0xFFFFFFFF and rolls over to 0, in both modes. */
    bool NextRollover(uint64_t after, uint64_t& at) const {
        if (free_run_) {
            const uint64_t first = base_ == 0u ? kWrap : kWrap - base_;
            at = Earliest(first, kWrap, after);
            return true;
        }
        const uint64_t z = FirstZero();
        if (ocr1_ == 0xFFFFFFFFu) {
            at = Earliest(z, kWrap, after);
            return true;
        }
        if (base_ > ocr1_ && z > after) {
            at = z;
            return true;
        }
        return false;
    }

private:
    static constexpr uint64_t kWrap = uint64_t{1} << 32;

    uint64_t Period() const { return uint64_t{ocr1_} + 1u; }

    uint64_t FirstZero() const {
        return base_ <= ocr1_ ? uint64_t{ocr1_} - base_ + 1u : kWrap - base_;
    }

    static uint64_t Earliest(uint64_t first, uint64_t period, uint64_t after) {
        if (first > after) return first;
        return first + ((after - first) / period + 1u) * period;
    }

    static uint64_t EarliestFrom(uint64_t first, uint64_t period, uint64_t from) {
        if (first >= from) return first;
        return first + ((from - first + period - 1u) / period) * period;
    }

    uint32_t base_;
    bool     free_run_;
    uint32_t ocr1_;
};

}
