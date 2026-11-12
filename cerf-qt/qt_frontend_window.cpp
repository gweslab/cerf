#include "frontend_window_adapter.h"
#include "qt_emulator_window.h"

#include <cerfcore/core/cerf_emulator.h>

namespace {

class QtFrontendWindow final : public cerffrontend::FrontendWindowAdapter {
public:
    using cerffrontend::FrontendWindowAdapter::FrontendWindowAdapter;

protected:
    cerffrontend::FrontendWindow& PlatformWindow() const override { return emu_.Get<QtEmulatorWindow>(); }
};

}

REGISTER_SERVICE_AS(QtFrontendWindow, cerffrontend::FrontendWindow);
