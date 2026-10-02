#pragma once

#include "../../core/service.h"

#include <cstdint>

class Rtc8564Wiring : public Service {
public:
    using Service::Service;

    struct Retained {
        uint8_t control2      = 0;
        uint8_t alarm[4]      = {};
        uint8_t clkout        = 0;
        uint8_t timer_control = 0;
        uint8_t timer         = 0;
    };

    virtual void     SetInterrupt(bool active) = 0;
    virtual int      CalendarYearBase() const = 0;
    virtual Retained RetainedRegisters() const = 0;
};
