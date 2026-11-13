#pragma once

#include "manager_windows.h"

#include <cerfcore/core/service.h>

#include <cstdint>

namespace cerffrontend {

class LivePropertySheet : public cerfcore::Service {
public:
    using cerfcore::Service::Service;

    bool Open(const char* page, bool force_reboot);

private:
    void ApplyGuestAdditions(GuestReset reset, uint32_t prev_w, uint32_t prev_h);
};

}
