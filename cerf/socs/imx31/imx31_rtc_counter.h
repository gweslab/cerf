#pragma once

#include <cstdint>

class StateReader;
class StateWriter;

class Imx31RtcCounter {
public:
    /* MCIMX31RM Table 36-9: RTCISR source bits. */
    static constexpr uint32_t kSw      = 1u << 0;
    static constexpr uint32_t kMin     = 1u << 1;
    static constexpr uint32_t kAlm     = 1u << 2;
    static constexpr uint32_t kDay     = 1u << 3;
    static constexpr uint32_t k1Hz     = 1u << 4;
    static constexpr uint32_t kHr      = 1u << 5;
    static constexpr uint32_t k2Hz     = 1u << 7;
    static constexpr uint32_t kSam0    = 1u << 8;
    static constexpr uint32_t kSources = 0x0000FFBFu;

    /* MCIMX31RM §36.4.1: a 24-hour clock over 65536 days. */
    static constexpr uint64_t kSecondsPerDay = 86400u;
    static constexpr uint64_t kWrapSeconds   = 65536u * kSecondsPerDay;
    static constexpr uint64_t kNever         = ~0ull;

    /* MCIMX31RM §36.4.4: "When the stopwatch value reaches -1, the interrupt occurs. The value
       of the register does not change until it is reprogrammed." */
    static constexpr uint8_t kStopwatchExpired = 0x3Fu;

    void     SetDivisor(uint64_t ref_per_second) { div_ = ref_per_second; }
    uint64_t Divisor() const { return div_; }

    uint64_t Seconds(uint64_t p) const;
    void     SetSeconds(uint64_t p, uint64_t total);
    void     SetAlarm(bool valid, uint64_t total);
    void     SetStopwatch(uint8_t count) { sw_ = count; }
    uint8_t  Stopwatch() const { return sw_; }

    uint32_t Advance(uint64_t p);
    uint64_t NextEvent(uint32_t sources) const;

    void Save(StateWriter& w) const;
    void Restore(StateReader& r);

private:
    static uint64_t CountHits(uint64_t base, uint64_t j_lo, uint64_t j_hi, uint64_t mod,
                              uint64_t residue);
    static uint64_t FirstHit(uint64_t base, uint64_t j_lo, uint64_t mod, uint64_t residue);

    uint64_t NextSecondHit(uint64_t mod, uint64_t residue) const;

    uint64_t div_          = 32768u;
    uint64_t sec_offset_   = 0;
    uint64_t eval_p_       = 0;
    bool     alarm_valid_  = true;
    uint64_t alarm_total_  = 0;
    uint8_t  sw_           = 0;
};
