#pragma once

#include "../../core/service.h"

#include <cstdint>

class Imx51ClockInput : public Service {
public:
    using Service::Service;

    virtual uint64_t OscHz() const = 0;
    virtual uint64_t CkilHz() const = 0;
};
