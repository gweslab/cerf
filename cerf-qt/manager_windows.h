#pragma once

#include <cerfcore/core/service.h>

#include <optional>

namespace cerffrontend {

enum class GuestReset { kNone, kSoft, kHard };

class ManagerWindows : public cerfcore::Service {
public:
    using cerfcore::Service::Service;

    virtual bool EditLiveCustomizations(bool force_reboot, std::optional<int> ce_major,
                                        GuestReset& reset) = 0;
};

}
