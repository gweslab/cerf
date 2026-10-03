#pragma once

#include "../../jit/guest_cycle_clock.h"
#include "../../socs/rated_tick_count.h"

#include <cstdint>
#include <functional>

class CerfEmulator;
class StateWriter;
class StateReader;

class OdoArm720PenTimer {
public:
    OdoArm720PenTimer(CerfEmulator& emu, std::function<void()> on_period,
                      std::function<bool()> status_set)
        : emu_(emu), on_period_(std::move(on_period)), status_set_(std::move(status_set)) {}

    void Attach();
    void SetEnabled(bool enabled);
    void OnStatusCleared();

    void SaveState(StateWriter& w);
    void RestoreState(StateReader& r);

private:
    void ArmNext(uint64_t now);
    void OnPeriod();
    void RequireGrid(bool placed, const char* what);
    void OnRateChange();

    CerfEmulator&           emu_;
    std::function<void()>   on_period_;
    std::function<bool()>   status_set_;
    GuestCycleClock*        clock_   = nullptr;
    GuestCycleClock::Event* event_   = nullptr;
    RatedTickCount          grid_;
    bool                    enabled_ = false;
};
