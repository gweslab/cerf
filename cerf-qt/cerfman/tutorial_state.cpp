#include "tutorial_state.h"

#include "../frontend_config.h"

#include <cerfcore/core/cerf_emulator.h>

#include <nlohmann/json.hpp>

#include <string>

REGISTER_SERVICE(TutorialState);

bool TutorialState::Finished() const { return emu_.Get<cerffrontend::FrontendConfig>().TutorialFinished(); }

QString TutorialState::Finish() {
    using cerffrontend::FrontendConfig;
    std::string error;
    auto&       config  = emu_.Get<FrontendConfig>();
    const bool  written = config.Write(
        [&config](nlohmann::ordered_json& j) {
            config.Assign(j, FrontendConfig::Key() / FrontendConfig::kTutorialFinishedKey, true);
        },
        error);
    emit changed();
    return written ? QString() : QString::fromStdString(error);
}
