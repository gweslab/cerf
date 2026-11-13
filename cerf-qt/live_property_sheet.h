#pragma once

#include "manager_windows.h"

#include <cerfcore/core/instance_gate.h>
#include <cerfcore/core/service.h>

#include <cstdint>
#include <functional>
#include <memory>
#include <vector>

namespace cerffrontend {

class LivePropertySheet : public cerfcore::Service {
public:
    using Done = std::function<void(bool accepted)>;

    using cerfcore::Service::Service;

    void Open(const char* page, bool force_reboot, Done done = {});

private:
    using Waiters = std::vector<Done>;

    void Finish(bool accepted, GuestReset reset, const Waiters& waiters);
    void ApplyGuestAdditions(GuestReset reset, uint32_t prev_w, uint32_t prev_h);

    std::shared_ptr<Waiters>     waiters_;
    const cerfcore::InstanceGate gate_{emu_};
};

}
