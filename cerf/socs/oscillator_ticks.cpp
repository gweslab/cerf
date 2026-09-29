#include "oscillator_ticks.h"

#include "../core/cerf_emulator.h"
#include "../core/fatal.h"
#include "../host/guest_deep_sleep.h"
#include "../state/state_stream.h"

namespace {

constexpr uint64_t kNsPerSec  = 1000000000u;
constexpr uint64_t kMaxNumDen = static_cast<uint64_t>(INT64_MAX) / kNsPerSec;

bool RateFits(uint64_t num, uint64_t den) {
    return num != 0u && den != 0u && num <= kMaxNumDen / den;
}

}

void OscillatorTicks::Attach(uint64_t osc_num, uint64_t osc_den) {
    if (!RateFits(osc_num, osc_den)) {
        emu_.Get<Fatal>().Die("OscillatorTicks: the oscillator rate %llu/%llu Hz",
                              static_cast<unsigned long long>(osc_num),
                              static_cast<unsigned long long>(osc_den));
    }
    clock_   = &emu_.Get<GuestCycleClock>();
    sleep_   = &emu_.Get<GuestDeepSleep>();
    osc_num_ = osc_num;
    osc_den_ = osc_den;
    Rebase();
}

uint64_t OscillatorTicks::ClockCycles() { return clock_->Cycles(); }

uint64_t OscillatorTicks::Scale() const { return kNsPerSec * osc_den_; }

bool OscillatorTicks::SetRatio() {
    return ticks_.SetRate(clock_->ClockRate(), OscRate());
}

void OscillatorTicks::RatioOverflow() {
    const GuestCycleClock::Rate rate = clock_->ClockRate();
    emu_.Get<Fatal>().Die("OscillatorTicks: the %llu/%llu Hz core against the %llu/%llu Hz "
                          "oscillator overflows the 64-bit scale",
                          static_cast<unsigned long long>(rate.num),
                          static_cast<unsigned long long>(rate.den),
                          static_cast<unsigned long long>(osc_num_),
                          static_cast<unsigned long long>(osc_den_));
}

uint64_t OscillatorTicks::CreditNs(uint64_t ns) {
    const uint64_t scale = Scale();
    const uint64_t part  = (ns % scale) * osc_num_ + credit_rem_;
    const uint64_t whole = ns / scale;
    const uint64_t carry = part / scale;
    if (whole > (UINT64_MAX - carry) / osc_num_ || !ticks_.AddTicks(whole * osc_num_ + carry)) {
        emu_.Get<Fatal>().Die("OscillatorTicks: a %llu ns credit overflows the tick count",
                              static_cast<unsigned long long>(ns));
    }
    credit_rem_ = part % scale;
    return whole * osc_num_ + carry;
}

void OscillatorTicks::DrainPark() {
    if (!credits_park_) return;
    const int64_t total = sleep_->SleptNs();
    if (total == slept_seen_) return;
    const uint64_t ns = static_cast<uint64_t>(total - slept_seen_);
    slept_seen_       = total;
    park_ticks_ += CreditNs(ns);
}

void OscillatorTicks::CreditAwakeNs(uint64_t ns) {
    DrainPark();
    CreditNs(ns);
}

uint64_t OscillatorTicks::Now() {
    DrainPark();
    return ticks_.TicksAt(ClockCycles());
}

OscillatorTicks::Reading OscillatorTicks::Sample() {
    DrainPark();
    return Reading{ticks_.TicksAt(ClockCycles()), park_ticks_};
}

uint64_t OscillatorTicks::CycleOf(uint64_t tick) {
    if (ClockStopped()) {
        emu_.Get<Fatal>().Die("OscillatorTicks: the cycle of a tick asked while the oscillator's "
                              "clock is stopped");
    }
    const uint64_t cycle = clock_->Cycles();
    if (tick <= Now()) return cycle;
    return ticks_.CycleOfTick(tick) + (cycle - ClockCycles());
}

void OscillatorTicks::ArmAt(GuestCycleClock::Event* event, uint64_t tick) {
    if (ClockStopped()) {
        clock_->Disarm(event);
        return;
    }
    clock_->Arm(event, CycleOf(tick));
}

int64_t OscillatorTicks::SleptNsAtTick(uint64_t tick) {
    if (!credits_park_) {
        emu_.Get<Fatal>().Die("OscillatorTicks: a park wake due on a counter that stops in the park");
    }
    const uint64_t now = Now();
    if (tick <= now) return slept_seen_;
    const uint64_t scale = Scale();
    const uint64_t ticks = tick - now;
    const uint64_t whole = ticks / osc_num_;
    const int64_t  num   = static_cast<int64_t>(osc_num_);
    const int64_t  part  = static_cast<int64_t>((ticks % osc_num_) * scale) -
                          static_cast<int64_t>(credit_rem_);
    const int64_t  part_ns = part >= 0 ? part / num + (part % num != 0 ? 1 : 0) : -((-part) / num);
    const uint64_t headroom =
        static_cast<uint64_t>(GuestDeepSleep::kNoParkWake - slept_seen_);
    if (whole > headroom / scale) return GuestDeepSleep::kNoParkWake;
    const uint64_t whole_ns = whole * scale;
    if (part_ns > 0 && whole_ns > headroom - static_cast<uint64_t>(part_ns))
        return GuestDeepSleep::kNoParkWake;
    return slept_seen_ + static_cast<int64_t>(whole_ns) + part_ns;
}

void OscillatorTicks::RescaleAt(uint64_t now) {
    if (!ticks_.Rescale(now, clock_->ClockRate(), OscRate())) RatioOverflow();
}

void OscillatorTicks::Rescale() { RescaleAt(ClockCycles()); }

void OscillatorTicks::SetOscRate(uint64_t osc_num, uint64_t osc_den) {
    if (osc_num == osc_num_ && osc_den == osc_den_) return;
    if (!RateFits(osc_num, osc_den) || osc_den > kMaxNumDen / osc_den_) {
        emu_.Get<Fatal>().Die("OscillatorTicks: the oscillator rate %llu/%llu Hz",
                              static_cast<unsigned long long>(osc_num),
                              static_cast<unsigned long long>(osc_den));
    }
    DrainPark();
    const uint64_t now     = ClockCycles();
    const uint64_t old_den = osc_den_;
    osc_num_    = osc_num;
    osc_den_    = osc_den;
    credit_rem_ = credit_rem_ * osc_den / old_den;
    if (!ticks_.Rescale(now, clock_->ClockRate(), OscRate())) RatioOverflow();
}

void OscillatorTicks::Rebase() {
    if (!SetRatio()) RatioOverflow();
    ticks_.Start(ClockCycles());
    park_ticks_ = 0;
    credit_rem_   = 0;
    slept_seen_ = sleep_->SleptNs();
}

void OscillatorTicks::Save(StateWriter& w) {
    DrainPark();
    const RatedTickCount::Position at = ticks_.PositionAt(ClockCycles());
    w.Write<uint64_t>("osc_num", osc_num_);
    w.Write<uint64_t>("osc_den", osc_den_);
    w.Write<uint64_t>("osc_ticks", at.ticks);
    w.Write<uint64_t>("osc_phase", at.phase);
    w.Write<uint64_t>("osc_phase_den", at.phase_den);
    w.Write<uint64_t>("osc_credit_rem", credit_rem_);
}

void OscillatorTicks::Restore(StateReader& r) {
    uint64_t osc_num = 0, osc_den = 0, ticks = 0, phase = 0, phase_den = 0, rem = 0;
    r.Read("osc_num", osc_num);
    r.Read("osc_den", osc_den);
    if (!RateFits(osc_num, osc_den)) {
        r.Reject("OscillatorTicks: restored oscillator rate %llu/%llu Hz",
                 static_cast<unsigned long long>(osc_num),
                 static_cast<unsigned long long>(osc_den));
    }
    osc_num_ = osc_num;
    osc_den_ = osc_den;
    r.Read("osc_ticks", ticks);
    r.Read("osc_phase", phase);
    r.Read("osc_phase_den", phase_den);
    r.Read("osc_credit_rem", rem);
    if (phase_den == 0u || phase >= phase_den || rem >= Scale()) {
        r.Reject("OscillatorTicks: restored phase %llu/%llu credit remainder %llu out of range",
                 static_cast<unsigned long long>(phase),
                 static_cast<unsigned long long>(phase_den),
                 static_cast<unsigned long long>(rem));
    }
    if (!SetRatio() ||
        !ticks_.PlaceAt(ClockCycles(), RatedTickCount::Position{ticks, phase, phase_den})) {
        r.Reject("OscillatorTicks: restored phase %llu/%llu does not fit the current core ratio",
                 static_cast<unsigned long long>(phase),
                 static_cast<unsigned long long>(phase_den));
    }
    park_ticks_ = 0;
    credit_rem_   = rem;
    slept_seen_ = sleep_->SleptNs();
}
