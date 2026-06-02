#pragma once

#include "../core/service.h"

#include <cstdint>
#include <string>

class BoardAtaService : public Service {
public:
    using Service::Service;

    virtual std::string GetImagePath()           = 0;
    virtual uint64_t    GetCapacityBytes() const = 0;

    /* Initialize the image only when absent/empty; a pre-existing non-empty
       image is the user's disk+data and must never be reformatted. */
    virtual void        EnsureExists()           = 0;
};
