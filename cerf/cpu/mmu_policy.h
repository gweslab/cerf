#pragma once

#include "../core/service.h"

#include <cstdint>

class MmuPolicy : public Service {
public:
    using Service::Service;

    virtual uint32_t TtbrL1BaseMask() const = 0;
};
