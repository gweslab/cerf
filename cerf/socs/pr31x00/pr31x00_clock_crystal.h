#pragma once

#include "../../core/service.h"

#include <cstdint>

class Pr31x00ClockCrystal : public Service {
public:
    using Service::Service;

    virtual uint64_t FinHz() const = 0;
};
