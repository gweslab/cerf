#include "enterprise_menu.h"

#include "enterprise_config.h"
#include "kiosk_mode.h"
#include "process_sign_in.h"

#include <cerfcore/core/cerf_emulator.h>

#include <utility>

namespace cerffrontend {

REGISTER_SERVICE(EnterpriseMenu);

std::vector<MenuItem> EnterpriseMenu::Items() {
    if (!emu_.Get<EnterpriseConfig>().Enabled()) return {};
    auto&    kiosk = emu_.Get<KioskMode>();
    MenuItem enter = MenuItem::Action("Enter kiosk mode", [this] { emu_.Get<KioskMode>().Enter(); });
    enter.enabled  = !kiosk.Active();
    std::vector<MenuItem> items;
    items.push_back(MenuItem{});
    items.push_back(std::move(enter));
    items.push_back(MenuItem::Action("Log out", [] { ProcessSignIn::SignOut(); }));
    return items;
}

}
