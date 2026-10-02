#pragma once

#include "../../core/service.h"
#include "../../jit/guest_cycle_clock.h"
#include "../cycle_anchored_counter.h"

#include <cstdint>

class StateReader;
class StateWriter;

class Iop13xxWatchdog : public Service {
public:
    using Service::Service;

    bool ShouldRegister() override;
    void OnReady() override;

    uint32_t ReadControl();
    void     WriteControl(uint32_t value);
    uint32_t ReadSetup() const { return setup_; }
    void     WriteSetup(uint32_t value);
    void     ClearPending();

    void SaveState(StateWriter& w);
    void RestoreState(StateReader& r);
    void PostRestore();

private:
    void SetBusRatio();
    void Advance(uint64_t cycle);
    void Arm();
    void OnEvent();
    void ResetState();
    void PublishLevel();

    GuestCycleClock*        clock_         = nullptr;
    GuestCycleClock::Event* event_         = nullptr;
    CycleAnchoredCounter    counter_;
    uint64_t                terminal_      = 0;
    uint32_t                setup_         = 0;
    bool                    enabled_       = false;
    bool                    enable_armed_  = false;
    bool                    disable_armed_ = false;
    bool                    expired_       = false;
    bool                    ever_enabled_  = false;
    bool                    pending_       = false;
    bool                    published_     = false;
};
