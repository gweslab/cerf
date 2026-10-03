#include "odo_arm720_pen_timer.h"

#include "../../core/cerf_emulator.h"
#include "../../core/fatal.h"
#include "../../state/state_stream.h"

namespace {

constexpr GuestCycleClock::Rate kPenTimingRate{200u, 1u};

}

void OdoArm720PenTimer::Attach() {
    clock_ = &emu_.Get<GuestCycleClock>();
    event_ = clock_->Add([this] { OnPeriod(); });
    clock_->RegisterRateListener([this] { OnRateChange(); });
}

void OdoArm720PenTimer::SetEnabled(bool enabled) {
    if (enabled == enabled_) return;
    enabled_ = enabled;
    if (!enabled) {
        clock_->Disarm(event_);
        return;
    }
    const uint64_t now = clock_->Cycles();
    RequireGrid(grid_.SetRate(clock_->ClockRate(), kPenTimingRate), "the pen timing grid");
    grid_.Start(now);
    ArmNext(now);
}

void OdoArm720PenTimer::OnStatusCleared() {
    if (enabled_) ArmNext(clock_->Cycles());
}

void OdoArm720PenTimer::ArmNext(uint64_t now) {
    if (status_set_()) {
        clock_->Disarm(event_);
        return;
    }
    clock_->Arm(event_, grid_.CycleOfTick(grid_.TicksAt(now) + 1u));
}

void OdoArm720PenTimer::OnPeriod() {
    on_period_();
    ArmNext(clock_->Cycles());
}

void OdoArm720PenTimer::RequireGrid(bool placed, const char* what) {
    if (placed) return;
    const GuestCycleClock::Rate core = clock_->ClockRate();
    emu_.Get<Fatal>().Die(
        "odo touch: %s does not fit the 64-bit scale of the %llu Hz pen timing "
        "against the %llu/%llu Hz core", what,
        static_cast<unsigned long long>(kPenTimingRate.num),
        static_cast<unsigned long long>(core.num),
        static_cast<unsigned long long>(core.den));
}

void OdoArm720PenTimer::OnRateChange() {
    if (!enabled_) return;
    const uint64_t now = clock_->Cycles();
    RequireGrid(grid_.Rescale(now, clock_->ClockRate(), kPenTimingRate),
                "the pen timing grid at the new core rate");
    ArmNext(now);
}

void OdoArm720PenTimer::SaveState(StateWriter& w) {
    const RatedTickCount::Position at =
        enabled_ ? grid_.PositionAt(clock_->Cycles()) : RatedTickCount::Position{};
    w.Write<uint32_t>("pen_timing_en", enabled_ ? 1u : 0u);
    w.Write<uint64_t>("pen_timing_phase", at.phase);
    w.Write<uint64_t>("pen_timing_phase_den", at.phase_den);
}

void OdoArm720PenTimer::RestoreState(StateReader& r) {
    uint64_t phase = 0, phase_den = 0;
    uint32_t en    = 0;
    r.Read("pen_timing_en", en);
    r.Read("pen_timing_phase", phase);
    r.Read("pen_timing_phase_den", phase_den);
    enabled_ = en != 0u;
    if (!enabled_) {
        clock_->Disarm(event_);
        return;
    }
    const uint64_t now = clock_->Cycles();
    RequireGrid(grid_.SetRate(clock_->ClockRate(), kPenTimingRate) &&
                    grid_.PlaceAt(now, RatedTickCount::Position{0u, phase, phase_den}),
                "the restored pen timing grid");
    ArmNext(now);
}
