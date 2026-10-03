#pragma once

#include "../../core/service.h"
#include "../../jit/guest_cycle_clock.h"

#include <functional>
#include <vector>

class Sa11xxSspClockInput : public Service {
public:
    using Service::Service;

    virtual bool Frequency(GuestCycleClock::Rate& hz) const = 0;

    void RegisterChangeListener(std::function<void()> fn);

protected:
    void NotifyChange();

private:
    std::vector<std::function<void()>> listeners_;
};
