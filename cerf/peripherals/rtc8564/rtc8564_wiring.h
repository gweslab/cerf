#pragma once

#include "../../core/service.h"

class Rtc8564Wiring : public Service {
public:
    using Service::Service;

    virtual void SetInterrupt(bool active) = 0;
    virtual int CalendarYearBase() const = 0;
};
