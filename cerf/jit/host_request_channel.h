#pragma once

#include <functional>
#include <vector>

#include "../core/service.h"

class HostRequestChannel : public Service {
public:
    using Service::Service;

    void RegisterListener(std::function<void()> fn);
    void Request() { Kick(); }
    void ServiceRequests();

protected:
    virtual void Kick() = 0;

private:
    std::vector<std::function<void()>> listeners_;
};
