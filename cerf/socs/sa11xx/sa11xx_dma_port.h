#pragma once

#include "../../jit/guest_cycle_clock.h"

#include <cstdint>

class Sa11xxDmaPort {
public:
    virtual ~Sa11xxDmaPort() = default;

    virtual uint32_t DeviceAddress() const = 0;
    virtual bool     Receive() const = 0;
    virtual uint32_t DatumBytes() const = 0;

    virtual void     Settle(uint64_t now) = 0;
    virtual void     SetSupply(uint64_t now, uint64_t words) = 0;
    virtual uint64_t Moved() const = 0;
    virtual bool     CycleOfMoved(uint64_t words, uint64_t& cycle) = 0;
    virtual GuestCycleClock::Rate WordRate() const = 0;
};
