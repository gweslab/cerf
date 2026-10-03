#pragma once

#include "../../jit/guest_cycle_clock.h"

#include <cstdint>

class Sa11xxDmaTransmitObserver {
public:
    virtual ~Sa11xxDmaTransmitObserver() = default;

    virtual void OnTransmitBlock(uint32_t ddar, uint32_t pa, uint32_t bytes,
                                 GuestCycleClock::Rate word_rate) = 0;
    virtual void OnTransmitStop(uint32_t ddar) = 0;
    virtual void OnTransmitRestored() = 0;
};

class Sa11xxDmaReceiveSource {
public:
    virtual ~Sa11xxDmaReceiveSource() = default;

    virtual bool FillReceived(uint32_t ddar, uint32_t pa, uint32_t bytes,
                              GuestCycleClock::Rate word_rate) = 0;
};
