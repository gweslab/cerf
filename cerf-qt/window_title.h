#pragma once

#include <cerfcore/core/service.h>

#include <string>

namespace cerffrontend {

class WindowTitle : public cerfcore::Service {
public:
    using cerfcore::Service::Service;

    std::string Compose() const;
};

}
