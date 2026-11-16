#include "../kiosk_mode.h"
#include "../password_gated_actions.h"

#include <cerfcore/core/cerf_emulator.h>

#include <utility>

namespace {

class AndroidKioskMode : public cerffrontend::KioskMode {
public:
    using cerffrontend::KioskMode::KioskMode;

    void CloseRequested(std::function<void()> proceed) override {
        emu_.Get<cerffrontend::PasswordGatedActions>().RunSignedIn(std::move(proceed));
    }

protected:
    void Lock() override {}
    void Unlock() override {}
};

}

REGISTER_SERVICE_AS(AndroidKioskMode, cerffrontend::KioskMode);
