#include "../manager_windows.h"
#include "qt_manager_window_opener.h"

#include <cerfcore/core/cerf_emulator.h>

#include <optional>

namespace {

class QtManagerWindows final : public cerffrontend::ManagerWindows {
public:
    using cerffrontend::ManagerWindows::ManagerWindows;

    bool EditLiveCustomizations(bool force_reboot, std::optional<int> ce_major,
                                cerffrontend::GuestReset& reset) override {
        return emu_.Get<QtManagerWindowOpener>().EditLiveCustomizations(force_reboot, ce_major, reset);
    }
};

}

REGISTER_SERVICE_AS(QtManagerWindows, cerffrontend::ManagerWindows);
