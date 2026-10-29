#include "tutorial_state.h"

#include "../frontend_config.h"

#include <cerfcore/core/cerf_emulator.h>

#include <nlohmann/json.hpp>

#include <string>

REGISTER_SERVICE(TutorialState);

bool TutorialState::Finished() const { return emu_.Get<cerffrontend::FrontendConfig>().TutorialFinished(); }

QString TutorialState::Finish() {
    std::string error;
    const bool  written = emu_.Get<cerffrontend::FrontendConfig>().Write(
        [](nlohmann::ordered_json& j) { j[cerffrontend::FrontendConfig::kTutorialFinishedKey] = true; }, error);
    emit changed();
    return written ? QString() : QString::fromStdString(error);
}
