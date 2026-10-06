#include "imx31_rtc_counter.h"

#include "../../state/state_stream.h"

#include <algorithm>

namespace {

constexpr uint64_t kSecondsPerMinute = 60u;
constexpr uint64_t kSecondsPerHour   = 3600u;

/* MCIMX31RM Table 36-14: SAM7..SAM0 run at the reference clock / 64 .. / 8192. */
constexpr uint32_t kSamCount  = 8u;
constexpr uint64_t kSam0Ratio = 8192u;

}

uint64_t Imx31RtcCounter::Seconds(uint64_t p) const {
    return (sec_offset_ + (p / div_) % kWrapSeconds) % kWrapSeconds;
}

void Imx31RtcCounter::SetSeconds(uint64_t p, uint64_t total) {
    sec_offset_ = (total % kWrapSeconds + kWrapSeconds - (p / div_) % kWrapSeconds) % kWrapSeconds;
}

void Imx31RtcCounter::SetAlarm(bool valid, uint64_t total) {
    alarm_valid_ = valid;
    alarm_total_ = total % kWrapSeconds;
}

uint64_t Imx31RtcCounter::FirstHit(uint64_t base, uint64_t j_lo, uint64_t mod, uint64_t residue) {
    const uint64_t at = (base % mod + j_lo % mod) % mod;
    return j_lo + (residue % mod + mod - at) % mod;
}

uint64_t Imx31RtcCounter::CountHits(uint64_t base, uint64_t j_lo, uint64_t j_hi, uint64_t mod,
                                    uint64_t residue) {
    if (j_hi < j_lo) return 0u;
    const uint64_t first = FirstHit(base, j_lo, mod, residue);
    if (first > j_hi) return 0u;
    return (j_hi - first) / mod + 1u;
}

uint32_t Imx31RtcCounter::Advance(uint64_t p) {
    if (p <= eval_p_) return 0u;
    const uint64_t from = eval_p_;
    eval_p_ = p;

    uint32_t       flags = 0u;
    const uint64_t j_lo  = from / div_ + 1u;
    const uint64_t j_hi  = p / div_;
    if (j_hi >= j_lo) {
        flags |= k1Hz;
        const uint64_t minutes = CountHits(sec_offset_, j_lo, j_hi, kSecondsPerMinute, 0u);
        if (minutes != 0u) flags |= kMin;
        if (CountHits(sec_offset_, j_lo, j_hi, kSecondsPerHour, 0u) != 0u) flags |= kHr;
        if (CountHits(sec_offset_, j_lo, j_hi, kSecondsPerDay, 0u) != 0u) flags |= kDay;
        if (alarm_valid_ && CountHits(sec_offset_, j_lo, j_hi, kWrapSeconds, alarm_total_) != 0u)
            flags |= kAlm;
        if (minutes != 0u) {
            if (sw_ == kStopwatchExpired || minutes > sw_) {
                sw_ = kStopwatchExpired;
                flags |= kSw;
            } else {
                sw_ = static_cast<uint8_t>(sw_ - minutes);
            }
        }
    }
    const uint64_t half = div_ / 2u;
    if (p / half > from / half) flags |= k2Hz;
    for (uint32_t n = 0; n < kSamCount; ++n) {
        const uint64_t q = kSam0Ratio >> n;
        if (p / q > from / q) flags |= kSam0 << n;
    }
    return flags;
}

uint64_t Imx31RtcCounter::NextSecondHit(uint64_t mod, uint64_t residue) const {
    return FirstHit(sec_offset_, eval_p_ / div_ + 1u, mod, residue) * div_;
}

uint64_t Imx31RtcCounter::NextEvent(uint32_t sources) const {
    uint64_t next = kNever;
    const auto take = [&next](uint64_t p) { next = std::min(next, p); };
    if (sources & k1Hz) take((eval_p_ / div_ + 1u) * div_);
    if (sources & k2Hz) {
        const uint64_t half = div_ / 2u;
        take((eval_p_ / half + 1u) * half);
    }
    for (uint32_t n = 0; n < kSamCount; ++n) {
        if ((sources & (kSam0 << n)) == 0u) continue;
        const uint64_t q = kSam0Ratio >> n;
        take((eval_p_ / q + 1u) * q);
    }
    if (sources & kMin) take(NextSecondHit(kSecondsPerMinute, 0u));
    if (sources & kHr) take(NextSecondHit(kSecondsPerHour, 0u));
    if (sources & kDay) take(NextSecondHit(kSecondsPerDay, 0u));
    if ((sources & kAlm) && alarm_valid_) take(NextSecondHit(kWrapSeconds, alarm_total_));
    if (sources & kSw) {
        const uint64_t minute = NextSecondHit(kSecondsPerMinute, 0u);
        const uint64_t ahead  = sw_ == kStopwatchExpired ? 0u : sw_;
        take(minute + ahead * kSecondsPerMinute * div_);
    }
    return next;
}

void Imx31RtcCounter::Save(StateWriter& w) const {
    w.Write<uint64_t>("rtc_sec_offset", sec_offset_);
    w.Write<uint64_t>("rtc_eval_p", eval_p_);
    w.Write<uint8_t>("rtc_stopwatch", sw_);
}

void Imx31RtcCounter::Restore(StateReader& r) {
    r.Read("rtc_sec_offset", sec_offset_);
    r.Read("rtc_eval_p", eval_p_);
    r.Read("rtc_stopwatch", sw_);
}
