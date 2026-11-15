#pragma once

#include <cerfcore/core/service.h>

namespace cerffrontend {

class CustomizationsEditor : public cerfcore::Service {
public:
    using cerfcore::Service::Service;

    virtual void Open() = 0;
};

}
