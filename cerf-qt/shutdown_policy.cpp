#include "shutdown_policy.h"

#include <cerfcore/core/cerf_emulator.h>

#include <algorithm>

namespace cerffrontend {

REGISTER_SERVICE(ShutdownPolicy);

using json = nlohmann::ordered_json;

namespace {

struct ActionId {
    ShutdownAction action;
    const char*    id;
};

constexpr ActionId kActionIds[] = {
    {ShutdownAction::Exit, "exit"},
    {ShutdownAction::SoftReset, "soft_reset"},
    {ShutdownAction::HardReset, "hard_reset"},
    {ShutdownAction::SaveStateExit, "save_state_exit"},
    {ShutdownAction::SaveStateSuspendHost, "save_state_suspend_host"},
    {ShutdownAction::SaveStatePoweroffHost, "save_state_poweroff_host"},
    {ShutdownAction::SaveStateRestartHost, "save_state_restart_host"},
};

}

std::vector<ShutdownAction> ShutdownPolicy::AllActions() {
    std::vector<ShutdownAction> actions;
    for (const ActionId& entry : kActionIds) actions.push_back(entry.action);
    return actions;
}

const char* ShutdownPolicy::Id(ShutdownAction action) { return kActionIds[static_cast<int>(action)].id; }

json ShutdownPolicy::ToJson(const std::vector<ShutdownAction>& actions) {
    json ids = json::array();
    for (ShutdownAction action : actions) ids.push_back(Id(action));
    return ids;
}

FrontendConfig::Key ShutdownPolicy::Key() { return FrontendConfig::Key() / kSectionKey / kShutdownKey; }

bool ShutdownPolicy::Usable(const std::vector<ShutdownAction>& actions) { return !actions.empty(); }

std::vector<ShutdownAction> ShutdownPolicy::Actions() const {
    const json                  ids = emu_.Get<FrontendConfig>().Read().at(Key());
    std::vector<ShutdownAction> actions;
    for (const ActionId& entry : kActionIds)
        if (std::find(ids.begin(), ids.end(), json(entry.id)) != ids.end()) actions.push_back(entry.action);
    return actions;
}

}
