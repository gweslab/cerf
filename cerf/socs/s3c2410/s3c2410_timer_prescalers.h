#pragma once

#include "../../core/service.h"
#include "../rated_tick_count.h"

#include <cstdint>

class S3C2410Clocks;
class StateReader;
class StateWriter;

class S3C2410TimerPrescalers : public Service {
public:
    using Service::Service;

    static constexpr int kGroups = 2;

    bool ShouldRegister() override;
    void OnReady() override;

    void Restart(uint64_t now);
    void OnRateChange(uint64_t now);
    void Reload(int g, uint32_t prescaler, uint64_t now);

    bool Gated() const { return gated_; }

    /* S3C2410A UM printed p. 7-21 CLKCON [8]: "Control PCLK into PWMTIMER block". */
    uint64_t PulsesAt(int g, uint64_t cycle) const {
        const Group& grp = groups_[g];
        if (gated_) return grp.held.ticks;
        return cycle < grp.load_cycle ? grp.load_ticks : grp.ticks.TicksAt(cycle);
    }

    uint64_t CycleOfPulse(int g, uint64_t pulse) const {
        return groups_[g].ticks.CycleOfTick(pulse);
    }

    void SaveState(StateWriter& w, uint64_t now) const;
    void RestoreState(StateReader& r, uint32_t tcfg0, uint64_t now);

private:
    struct Group {
        RatedTickCount           ticks;
        RatedTickCount::Position held;
        GuestCycleClock::Rate    core{1u, 1u};
        GuestCycleClock::Rate    rate{1u, 1u};
        uint32_t                 prescaler  = 0;
        uint64_t                 load_cycle = 0;
        uint64_t                 load_ticks = 0;
    };

    GuestCycleClock::Rate CoreRate() const;
    GuestCycleClock::Rate PrescalerRate(uint32_t prescaler) const;
    [[noreturn]] void RateOverflow(int g) const;
    void LoadRates(int g, uint32_t prescaler);
    void Place(int g, uint64_t cycle, const RatedTickCount::Position& at);

    S3C2410Clocks* clocks_ = nullptr;
    bool           gated_  = false;
    Group          groups_[kGroups];
};
