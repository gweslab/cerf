#include "password_gated_actions.h"

#include "cerfman/password_gate.h"
#include "process_sign_in.h"
#include "qt_emulator_window.h"

#include <cerfcore/core/cerf_emulator.h>

#include <QString>

namespace cerffrontend {

REGISTER_SERVICE(PasswordGatedActions);

void PasswordGatedActions::OpenCerfman(const std::function<void()>& action, const std::function<void()>& refused) {
    if (emu_.Get<PasswordGate>().Locked()) RunSignedIn(action, refused);
    else                                   action();
}

void PasswordGatedActions::RunSignedIn(const std::function<void()>& action, const std::function<void()>& refused) {
    if (!ProcessSignIn::SignedIn() && !asking_) {
        asking_ = true;
        emu_.Get<QtEmulatorWindow>().RunDialog(QStringLiteral("EmulatorPasswordDialog"), {});
        asking_ = false;
    }
    if (ProcessSignIn::SignedIn()) action();
    else if (refused) refused();
}

}
