#pragma once

#include <cstdint>

#include "../../core/service.h"

class Sa11xxCoreClockTable : public Service {
public:
    using Service::Service;

    virtual uint32_t MaxCcf() const = 0;
};
