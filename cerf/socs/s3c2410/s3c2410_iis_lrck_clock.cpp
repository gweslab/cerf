#include "s3c2410_iis_lrck_clock.h"

#include "../../state/state_stream.h"

#include <numeric>

namespace {

constexpr uint64_t kMaxScale = 0xFFFFFFFFull;

}

bool S3C2410IisLrckClock::Units(uint64_t rate_num, uint64_t rate_den, uint64_t cpu_hz,
                                uint64_t* step, uint64_t* scale) {
    if (rate_num == 0u || rate_den == 0u || cpu_hz == 0u) return false;
    if (rate_den > UINT64_MAX / cpu_hz) return false;
    const uint64_t cycles = cpu_hz * rate_den;
    const uint64_t g      = std::gcd(rate_num, cycles);
    *step  = rate_num / g;
    *scale = cycles / g;
    return *step <= kMaxScale && *scale <= kMaxScale;
}

void S3C2410IisLrckClock::Start(uint64_t now, uint64_t rate_num, uint64_t rate_den,
                                uint64_t cpu_hz) {
    Units(rate_num, rate_den, cpu_hz, &step_, &scale_);
    rate_num_ = rate_num;
    rate_den_ = rate_den;
    hz_       = cpu_hz;
    anchor_   = now - restore_since_;
    rem_      = restore_rem_;
    right_    = restore_right_;
    ForgetRestored();
}

uint64_t S3C2410IisLrckClock::Take(uint64_t now) {
    const uint64_t acc    = (now - anchor_) * step_ + rem_;
    const uint64_t phases = acc / scale_;
    anchor_ = now;
    rem_    = acc % scale_;
    right_  = right_ != ((phases & 1u) != 0u);
    return phases;
}

uint64_t S3C2410IisLrckClock::CycleOf(uint64_t phases) const {
    const uint64_t need = phases * scale_ - rem_;
    return anchor_ + (need + step_ - 1u) / step_;
}

bool S3C2410IisLrckClock::Retime(uint64_t rate_num, uint64_t rate_den, uint64_t cpu_hz) {
    uint64_t step = 0, scale = 1;
    Units(rate_num, rate_den, cpu_hz, &step, &scale);
    rem_ = rem_ * scale / scale_;
    const bool changed = rate_num * rate_den_ != rate_num_ * rate_den;
    step_     = step;
    scale_    = scale;
    rate_num_ = rate_num;
    rate_den_ = rate_den;
    hz_       = cpu_hz;
    return changed;
}

void S3C2410IisLrckClock::ForgetRestored() {
    restore_since_ = 0;
    restore_rem_   = 0;
    restore_right_ = false;
}

void S3C2410IisLrckClock::Save(StateWriter& w, bool running, uint64_t now) const {
    w.Write<uint8_t>("draining", running ? 1u : 0u);
    w.Write<uint64_t>("drain_since", running ? now - anchor_ : 0u);
    w.Write<uint64_t>("drain_rem", running ? rem_ : 0u);
    w.Write<uint64_t>("drain_hz", running ? hz_ : 0u);
    w.Write<uint8_t>("drain_right", running && right_ ? 1u : 0u);
}

void S3C2410IisLrckClock::Restore(StateReader& r, uint64_t now, uint64_t cpu_hz,
                                  uint64_t rate_num, uint64_t rate_den,
                                  uint64_t max_phases) {
    uint8_t  draining = 0, right = 0;
    uint64_t hz = 0;
    r.Read("draining", draining);
    if (draining > 1u) r.Reject("draining flag %u is not 0 or 1", draining);
    r.Read("drain_since", restore_since_);
    r.Read("drain_rem", restore_rem_);
    r.Read("drain_hz", hz);
    r.Read("drain_right", right);
    if (right > 1u) r.Reject("drain channel flag %u is not 0 or 1", right);
    restore_right_ = right != 0u;
    if (draining == 0u && (restore_since_ != 0u || restore_rem_ != 0u || hz != 0u ||
                           restore_right_))
        r.Reject("drain phase carries values with no transmit in progress");
    if (draining == 0u) return;
    if (rate_num == 0u) r.Reject("drain phase saved with the transmitter not running");
    if (hz != cpu_hz)
        r.Reject("drain phase saved at %llu Hz against a restored core clock of %llu Hz",
                 static_cast<unsigned long long>(hz),
                 static_cast<unsigned long long>(cpu_hz));
    uint64_t step = 0, scale = 1;
    if (!Units(rate_num, rate_den, cpu_hz, &step, &scale))
        r.Reject("transmit rate %llu/%llu Hz has no phase units at %llu Hz",
                 static_cast<unsigned long long>(rate_num),
                 static_cast<unsigned long long>(rate_den),
                 static_cast<unsigned long long>(cpu_hz));
    const uint64_t max_since = max_phases * scale / step;
    if (restore_rem_ >= scale || restore_since_ > now || restore_since_ > max_since)
        r.Reject("drain phase since %llu rem %llu is not one the drain produces",
                 static_cast<unsigned long long>(restore_since_),
                 static_cast<unsigned long long>(restore_rem_));
}
