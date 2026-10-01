#pragma once

#include "../../core/service.h"

#include <cstdint>

class Imx31ClockInput : public Service {
public:
    using Service::Service;

    virtual uint64_t CkihHz() const = 0;
    virtual uint64_t CkilHz() const = 0;
    virtual bool     ResetReferenceIsCkih() const = 0;
};
