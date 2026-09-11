#pragma once

#include "../core/service.h"

#include <cstdint>

class PhysicalAddressMapper : public Service {
public:
    using Service::Service;

    virtual bool Map(uint64_t cpu_pa, uint32_t size, uint32_t& system_pa) = 0;
};
