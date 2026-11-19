#pragma once

#include <cerfcore/core/service.h>

#include <string>

namespace cerffrontend {

class AutomationEndpoint : public cerfcore::Service {
public:
    using cerfcore::Service::Service;

    virtual std::string Address() const = 0;
};

}
