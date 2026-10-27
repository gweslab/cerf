#include "../frontend_window_adapter.h"
#include "mobile_emulator_window.h"

#include <cerfcore/core/cerf_emulator.h>

namespace {

class MobileFrontendWindow final : public cerffrontend::FrontendWindowAdapter {
public:
    using cerffrontend::FrontendWindowAdapter::FrontendWindowAdapter;

protected:
    cerffrontend::FrontendWindow& PlatformWindow() const override { return emu_.Get<MobileEmulatorWindow>(); }
};

}

REGISTER_SERVICE_AS(MobileFrontendWindow, cerffrontend::FrontendWindow);
