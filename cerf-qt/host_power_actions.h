#pragma once

#include <cerfcore/core/service.h>

#include <functional>

namespace cerffrontend {

class HostPowerActions : public cerfcore::Service {
public:
    using cerfcore::Service::Service;

    void RequireSuspend();
    void Suspend(std::function<void()> after);

    [[noreturn]] void PowerOff();
    [[noreturn]] void Restart();
};

}
