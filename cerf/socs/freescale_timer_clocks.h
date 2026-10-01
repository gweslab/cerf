#pragma once

#include "../core/service.h"

#include <cstdint>
#include <functional>

enum class FreescaleTimerUnit : uint8_t { kEpit1, kEpit2, kGpt };

enum class FreescaleTimerInput : uint8_t { kIpg, kHighfreq, kLowfreq };

enum class FreescaleLowPowerMode : uint8_t { kRun, kWait, kDoze, kStop, kStateRetention };

class FreescaleTimerClocks : public Service {
public:
    using Service::Service;

    virtual uint64_t InputHz(FreescaleTimerUnit unit, FreescaleTimerInput input) const = 0;

    virtual bool InputRunsIn(FreescaleTimerUnit unit, FreescaleTimerInput input,
                             FreescaleLowPowerMode mode) const = 0;

    virtual FreescaleLowPowerMode WfiMode() const = 0;

    virtual void RegisterRateListener(std::function<void()> fn) = 0;
};
