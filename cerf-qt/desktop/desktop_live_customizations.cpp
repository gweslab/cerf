#include "qt_manager_window_opener.h"

#include "../manager_windows.h"

#include <cerfcore/core/cerf_emulator.h>

#include <utility>

namespace {

class DesktopLiveCustomizations final : public cerffrontend::ManagerWindows {
public:
    using cerffrontend::ManagerWindows::ManagerWindows;

    void EditLiveProperties(const char* page, bool force_reboot, std::optional<int> ce_major,
                            cerffrontend::LiveSheetFinished finished) override {
        emu_.Get<QtManagerWindowOpener>().EditLiveProperties(page, force_reboot, ce_major, std::move(finished));
    }
};

}

REGISTER_SERVICE_AS(DesktopLiveCustomizations, cerffrontend::ManagerWindows);
