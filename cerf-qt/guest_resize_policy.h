#pragma once

#include <cerfcore/core/service.h>

#include <cstdint>

namespace cerffrontend {

class GuestResizePolicy : public cerfcore::Service {
public:
    using cerfcore::Service::Service;

    virtual bool Available() const = 0;
    virtual bool Enabled() const = 0;
    virtual void SetEnabled(bool on) = 0;
    virtual void OnUserResizeEnd(uint32_t canvas_w, uint32_t canvas_h) = 0;
};

}
