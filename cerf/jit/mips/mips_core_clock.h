#pragma once

#include <cstdint>
#include <functional>
#include <vector>

#include "../../core/service.h"
#include "../guest_cycle_clock.h"

class MipsCoreClock : public Service {
public:
    using Service::Service;

    virtual GuestCycleClock::Rate ResetRate() const = 0;
    virtual uint64_t CyclesPerCountTick() const;
    virtual uint64_t CyclesPerTclkCounterTick() const;

    void RegisterCountRateListener(std::function<void()> fn);
    void CountRateRestored();

private:
    std::vector<std::function<void()>> count_rate_listeners_;
};
