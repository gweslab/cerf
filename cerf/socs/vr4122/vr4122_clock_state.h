#pragma once

#include "../../core/service.h"
#include "../../jit/guest_cycle_clock.h"

#include <cstdint>

class StateWriter;
class StateReader;

/* PMUTCLKDIVREG (VR4131 UM U15350EJ2V0UM 12.2.6) is the VTCLK/TCLK divider the PMU register
   and CLKSPEEDREG (BCU, 7.2.7 p142) both view; the setting "becomes valid after a reset
   other than an RTC reset occurs" (12.2.6). */
class Vr4122ClockState : public Service {
public:
    using Service::Service;

    bool ShouldRegister() override;
    void OnReady() override;

    void     SetPending(uint16_t tclkdiv);
    uint16_t Pending() const { return pending_; }
    uint16_t Active()  const { return active_; }

    uint16_t ClkSp() const { return clksp_; }
    uint16_t ClkSpeedReg() const;

    GuestCycleClock::Rate ResetRate() const;
    uint64_t              CyclesPerCountTick() const;
    uint64_t              CyclesPerTclkCounterTick() const;

    void SaveState(StateWriter& w) const;
    void RestoreState(StateReader& r);

private:
    uint16_t VtDivMode() const;
    uint16_t TDivMode() const;

    uint16_t pending_     = 0;
    uint16_t active_      = 0;
    uint16_t clksp_       = 0;
    uint16_t strap_vtdiv_ = 0;
};
