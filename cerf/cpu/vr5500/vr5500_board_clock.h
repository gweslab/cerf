#pragma once

#include "../../core/service.h"

#include <cstdint>

class Vr5500BoardClock : public Service {
public:
    using Service::Service;

    virtual uint64_t PClockHz() const = 0;
};
