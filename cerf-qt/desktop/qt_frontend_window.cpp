#include "../frontend_window_adapter.h"
#include "qt_main_window.h"

#include <cerfcore/core/cerf_emulator.h>

namespace {

class QtFrontendWindow final : public cerffrontend::FrontendWindowAdapter {
public:
    using cerffrontend::FrontendWindowAdapter::FrontendWindowAdapter;

protected:
    cerffrontend::FrontendWindow& PlatformWindow() const override { return emu_.Get<QtMainWindow>(); }
};

}

REGISTER_SERVICE_AS(QtFrontendWindow, cerffrontend::FrontendWindow);
