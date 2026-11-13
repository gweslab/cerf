#pragma once

#include <cerfcore/core/service.h>

#include <functional>
#include <optional>

namespace cerffrontend {

enum class GuestReset { kNone, kSoft, kHard };

using LiveSheetFinished = std::function<void(bool accepted, GuestReset reset)>;

class ManagerWindows : public cerfcore::Service {
public:
    using cerfcore::Service::Service;

    virtual void EditLiveProperties(const char* page, bool force_reboot, std::optional<int> ce_major,
                                    LiveSheetFinished finished) = 0;
};

}
