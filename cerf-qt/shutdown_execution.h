#pragma once

#include "shutdown_policy.h"

#include <cerfcore/core/service.h>

#include <functional>

namespace cerffrontend {

class ShutdownExecution : public cerfcore::Service {
public:
    using cerfcore::Service::Service;

    bool Run(ShutdownAction action, std::function<void(bool saved)> save_done);

private:
    bool SaveAndExit(bool suspend_host, std::function<void(bool saved)> save_done);

    bool saving_ = false;
};

}
