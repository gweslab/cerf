#pragma once

#include "../../core/service.h"
#include "../../jit/guest_cycle_clock.h"

#include <cstdint>

class StateWriter;
class StateReader;

class Pr31x00SibAudioSink : public Service {
public:
    using Service::Service;

    virtual void StartSoundTx(uint32_t src_pa, uint32_t bytes, GuestCycleClock::Rate rate) = 0;
    virtual void StopSoundTx() = 0;

    virtual void SaveState(StateWriter& w) = 0;
    virtual void RestoreState(StateReader& r) = 0;
};
