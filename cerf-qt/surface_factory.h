#pragma once

#include "painter.h"

#include <cerfcore/core/service.h>

#include <memory>

namespace cerffrontend {

class SurfaceFactory : public cerfcore::Service {
public:
    using cerfcore::Service::Service;

    virtual std::unique_ptr<OffscreenSurface> Create(int width, int height) = 0;
};

}
