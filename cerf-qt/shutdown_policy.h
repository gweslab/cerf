#pragma once

#include "frontend_config.h"

#include <cerfcore/core/service.h>

#include <nlohmann/json.hpp>

#include <vector>

namespace cerffrontend {

enum class ShutdownAction : int {
    Exit,
    SoftReset,
    HardReset,
    SaveStateExit,
    SaveStateSuspendHost,
    SaveStatePoweroffHost,
    SaveStateRestartHost,
};

class ShutdownPolicy : public cerfcore::Service {
public:
    using cerfcore::Service::Service;

    static constexpr char kSectionKey[]  = "policies";
    static constexpr char kShutdownKey[] = "shutdown";

    static std::vector<ShutdownAction> AllActions();
    static const char*                 Id(ShutdownAction action);
    static nlohmann::ordered_json      ToJson(const std::vector<ShutdownAction>& actions);
    static FrontendConfig::Key         Key();
    static bool                        Usable(const std::vector<ShutdownAction>& actions);

    std::vector<ShutdownAction> Actions() const;
};

}
