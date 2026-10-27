#pragma once

#include <cerfcore/core/service.h>

namespace cerffrontend {

class CliUsage : public cerfcore::Service {
public:
    using cerfcore::Service::Service;

    void Print(const char* prog);
};

}
