#pragma once

#include <cerfcore/core/service.h>

namespace cerffrontend {

enum class CalibWarningChoice { kDismissed, kSwitchToStock };

class CalibrationWarningPrompt : public cerfcore::Service {
public:
    using cerfcore::Service::Service;

    static constexpr const char* kTitle       = "Guest Additions Warning";
    static constexpr const char* kSwitchLabel = "Switch to stock input";
    static constexpr const char* kChangeLabel = "Change resolution";
    static constexpr const char* kCloseLabel  = "Close";

    virtual CalibWarningChoice Show()    = 0;
    virtual void               Dismiss() = 0;
};

}
