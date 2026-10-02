#include "s3c2410_timer_prescalers.h"

#include "../../boards/board_context.h"
#include "s3c2410_id.h"
#include "../../core/cerf_emulator.h"
#include "../../core/fatal.h"
#include "../../core/log.h"
#include "../../state/state_stream.h"
#include "s3c2410_clocks.h"
#include "s3c2410_timer_regs.h"

#include <algorithm>

REGISTER_SERVICE(S3C2410TimerPrescalers);

using S3C2410TimerRegs::Prescaler;

bool S3C2410TimerPrescalers::ShouldRegister() {
    auto* bd = emu_.TryGet<BoardContext>();
    return bd && bd->GetSocId() == SocId::S3c2410;
}

void S3C2410TimerPrescalers::OnReady() {
    clocks_ = &emu_.Get<S3C2410Clocks>();
    Restart(emu_.Get<GuestCycleClock>().Cycles());
}

/* S3C2410A UM printed p.10-1 "Two 8-bit prescalers & Two 4-bit divider"; p.10-2
   Figure 10-1: prescaler 0 and its divider feed timers 0-1, prescaler 1 and its
   divider feed timers 2-4; p.10-11 TCFG0: PCLK / {prescaler value+1} / {divider value}. */
GuestCycleClock::Rate S3C2410TimerPrescalers::CoreRate() const {
    return GuestCycleClock::Rate{clocks_->CoreClockHz(), 1u};
}

GuestCycleClock::Rate S3C2410TimerPrescalers::PrescalerRate(uint32_t prescaler) const {
    return GuestCycleClock::Rate{clocks_->PclkHz(), prescaler + 1u};
}

void S3C2410TimerPrescalers::RateOverflow(int g) const {
    emu_.Get<Fatal>().Die("S3C2410TimerPrescalers: prescaler %d rate %llu/%u Hz on a %llu Hz "
                          "core overflows the 64-bit scale", g,
                          static_cast<unsigned long long>(clocks_->PclkHz()),
                          groups_[g].prescaler + 1u,
                          static_cast<unsigned long long>(clocks_->CoreClockHz()));
}

void S3C2410TimerPrescalers::LoadRates(int g, uint32_t prescaler) {
    Group& grp    = groups_[g];
    grp.prescaler = prescaler;
    grp.core      = CoreRate();
    grp.rate      = PrescalerRate(prescaler);
}

void S3C2410TimerPrescalers::Place(int g, uint64_t cycle, const RatedTickCount::Position& at) {
    Group& grp = groups_[g];
    if (!grp.ticks.SetRate(grp.core, grp.rate)) RateOverflow(g);
    if (!grp.ticks.PlaceAt(cycle, at)) {
        emu_.Get<Fatal>().Die("S3C2410TimerPrescalers: prescaler %d phase %llu/%llu after pulse "
                              "%llu is not a fraction below one period (cycle %llu)", g,
                              static_cast<unsigned long long>(at.phase),
                              static_cast<unsigned long long>(at.phase_den),
                              static_cast<unsigned long long>(at.ticks),
                              static_cast<unsigned long long>(cycle));
    }
}

void S3C2410TimerPrescalers::Restart(uint64_t now) {
    gated_ = !clocks_->PwmTimerClockOn();
    for (int g = 0; g < kGroups; ++g) {
        Group& grp = groups_[g];
        LoadRates(g, 0u);
        Place(g, now, RatedTickCount::Position{});
        grp.held       = grp.ticks.PositionAt(now);
        grp.load_cycle = 0u;
        grp.load_ticks = 0u;
    }
}

void S3C2410TimerPrescalers::OnRateChange(uint64_t now) {
    const bool                  gated = !clocks_->PwmTimerClockOn();
    const GuestCycleClock::Rate core  = CoreRate();
    for (int g = 0; g < kGroups; ++g) {
        Group& grp = groups_[g];
        const GuestCycleClock::Rate rate = PrescalerRate(grp.prescaler);
        const bool changed = core.num != grp.core.num || core.den != grp.core.den ||
                             rate.num != grp.rate.num || rate.den != grp.rate.den;
        if ((changed || gated != gated_) && now < grp.load_cycle) {
            emu_.Get<Fatal>().Die("S3C2410TimerPrescalers: the clock of prescaler %d changes at "
                                  "cycle %llu, before the pulse at cycle %llu that loads its new "
                                  "value; not modelled", g, static_cast<unsigned long long>(now),
                                  static_cast<unsigned long long>(grp.load_cycle));
        }
        if (changed) {
            LOG(SocTimer, "S3C2410TimerPrescalers: prescaler %d %llu/%llu Hz on %llu Hz -> "
                "%llu/%llu Hz on %llu Hz at cycle %llu\n", g,
                static_cast<unsigned long long>(grp.rate.num),
                static_cast<unsigned long long>(grp.rate.den),
                static_cast<unsigned long long>(grp.core.num),
                static_cast<unsigned long long>(rate.num),
                static_cast<unsigned long long>(rate.den),
                static_cast<unsigned long long>(core.num),
                static_cast<unsigned long long>(now));
            grp.core = core;
            grp.rate = rate;
            if (!gated_ && !grp.ticks.Rescale(now, core, rate)) RateOverflow(g);
        }
        if (gated && !gated_) {
            grp.held = grp.ticks.PositionAt(now);
        } else if (!gated && gated_) {
            Place(g, now, grp.held);
        }
    }
    gated_ = gated;
}

void S3C2410TimerPrescalers::Reload(int g, uint32_t prescaler, uint64_t now) {
    Group& grp = groups_[g];
    const bool     loading = now < grp.load_cycle;
    const uint64_t pulses  = loading ? grp.load_ticks : grp.ticks.TicksAt(now);
    const uint64_t load    = loading ? grp.load_cycle : grp.ticks.CycleOfTick(pulses + 1u);
    LOG(SocTimer, "S3C2410TimerPrescalers: prescaler %d reloads %u -> %u at cycle %llu; the "
        "count in progress ends with the pulse at cycle %llu\n", g, grp.prescaler, prescaler,
        static_cast<unsigned long long>(now), static_cast<unsigned long long>(load));
    LoadRates(g, prescaler);
    Place(g, load, RatedTickCount::Position{pulses + 1u, 0u, 1u});
    grp.load_cycle = load;
    grp.load_ticks = pulses;
}

void S3C2410TimerPrescalers::SaveState(StateWriter& w, uint64_t now) const {
    for (int g = 0; g < kGroups; ++g) {
        const Group& grp = groups_[g];
        const uint64_t at = std::max(now, grp.load_cycle);
        const RatedTickCount::Position p = gated_ ? grp.held : grp.ticks.PositionAt(at);
        w.Write<uint64_t>("divider_ticks", p.ticks);
        w.Write<uint64_t>("divider_phase", p.phase);
        w.Write<uint64_t>("divider_phase_den", p.phase_den);
        w.Write<uint64_t>("divider_ahead", at - now);
    }
}

void S3C2410TimerPrescalers::RestoreState(StateReader& r, uint32_t tcfg0, uint64_t now) {
    gated_ = !clocks_->PwmTimerClockOn();
    for (int g = 0; g < kGroups; ++g) {
        Group& grp = groups_[g];
        uint64_t ahead = 0;
        r.Read("divider_ticks", grp.held.ticks);
        r.Read("divider_phase", grp.held.phase);
        r.Read("divider_phase_den", grp.held.phase_den);
        r.Read("divider_ahead", ahead);
        LoadRates(g, Prescaler(g, tcfg0));
        Place(g, now + ahead, grp.held);
        grp.load_cycle = ahead != 0u ? now + ahead : 0u;
        grp.load_ticks = ahead != 0u ? grp.held.ticks - 1u : 0u;
    }
}
