#include "qt_manager_window_opener.h"

#include "../manager_windows.h"

#include <cerfcore/core/cerf_emulator.h>

namespace {

class DesktopLiveCustomizations final : public cerffrontend::ManagerWindows {
public:
    using cerffrontend::ManagerWindows::ManagerWindows;

    bool EditLiveProperties(const char* page, bool force_reboot, std::optional<int> ce_major,
                            cerffrontend::GuestReset& reset) override {
        return emu_.Get<QtManagerWindowOpener>().EditLiveProperties(page, force_reboot, ce_major, reset);
    }
};

}

REGISTER_SERVICE_AS(DesktopLiveCustomizations, cerffrontend::ManagerWindows);
