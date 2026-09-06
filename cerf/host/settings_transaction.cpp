#define NOMINMAX
#include "settings_transaction.h"

#include "../core/cerf_emulator.h"
#include "launcher_transaction.h"

REGISTER_SERVICE(SettingsTransaction);

bool SettingsTransaction::Open(HWND owner) {
    const nlohmann::json query = nlohmann::json::object();
    nlohmann::json response;
    return emu_.Get<LauncherTransaction>().Run(owner, "settings", query,
                                               response);
}
