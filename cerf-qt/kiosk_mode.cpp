#include "kiosk_mode.h"

#include "enterprise_config.h"
#include "frontend_window.h"
#include "password_gated_actions.h"
#include "process_sign_in.h"

#include <cerfcore/core/cerf_emulator.h>
#include <cerfcore/core/log.h>
#include <cerfcore/core/product_name.h>
#include <cerfcore/host/user_alert.h>

#include <string>

namespace cerffrontend {

void KioskMode::OnReady() {
    active_ = emu_.Get<EnterpriseConfig>().Kiosk();
    if (active_) emu_.Get<FrontendWindow>().RunOnUiThread([this] { Lock(); });
}

bool KioskMode::Store(bool on) {
    std::string error;
    if (emu_.Get<EnterpriseConfig>().SetKiosk(on, error)) return true;
    LOG(Caution, "KioskMode: the kiosk setting was not saved: %s\n", error.c_str());
    emu_.Get<cerfcore::UserAlert>().Post(cerfcore::AlertLevel::kError, "Kiosk mode - " CERF_PRODUCT_NAME,
                                         "The kiosk mode setting was not saved.\n\n" + error, {});
    return false;
}

void KioskMode::Enter() {
    emu_.Get<PasswordGatedActions>().RunSignedIn([this] {
        if (!Store(true)) return;
        active_ = true;
        Lock();
        ProcessSignIn::SignOut();
        LOG(Manager, "KioskMode: entered\n");
    });
}

void KioskMode::Exit() {
    emu_.Get<PasswordGatedActions>().RunSignedIn([this] {
        if (!Store(false)) return;
        active_ = false;
        Unlock();
        LOG(Manager, "KioskMode: left\n");
    });
}

void KioskMode::NoteHostKeyTap() {
    if (!active_) {
        taps_ = 0;
        return;
    }
    const auto now = std::chrono::steady_clock::now();
    if (now - last_tap_ > kTapGap) taps_ = 0;
    last_tap_ = now;
    if (++taps_ < kExitTaps) return;
    taps_ = 0;
    emu_.Get<FrontendWindow>().RunOnUiThread([this] { Exit(); });
}

}
