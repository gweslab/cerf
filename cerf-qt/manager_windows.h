#pragma once

#include <cerfcore/core/service.h>
#include <cerfcore/state/guest_reset.h>

#include <functional>

namespace cerffrontend {

using GuestReset = cerfcore::GuestReset;

using LiveSheetFinished = std::function<void(bool accepted, GuestReset reset)>;

class ManagerWindows : public cerfcore::Service {
public:
    using cerfcore::Service::Service;

    virtual void EditLiveProperties(const char* page, bool force_reboot, bool live_resize,
                                    LiveSheetFinished finished) = 0;
};

}
