#include "frontend_config.h"
#include "cerfman/json_file.h"
#include "install_root_files.h"
#include "integer_scales.h"

#include <cerfcore/core/cerf_emulator.h>
#include <cerfcore/core/cerf_paths.h>
#include <cerfcore/core/config_json.h>
#include <cerfcore/core/config_reader.h>
#include <cerfcore/core/log.h>

#include <nlohmann/json.hpp>

namespace cerffrontend {

REGISTER_SERVICE(FrontendConfig);

std::vector<int> FrontendConfig::DefaultScaleValues() {
    std::vector<int> values{kDynamicScale, kOriginalScale};
    values.insert(values.end(), std::begin(kIntegerScales), std::end(kIntegerScales));
    return values;
}

std::vector<const char*> FrontendConfig::UpdateChannelValues() {
    return {kUpdateChannelDisabled, kUpdateChannelStable, kUpdateChannelUnstable};
}

using json = nlohmann::ordered_json;

namespace {

std::vector<uint8_t> ReadHostKey(const json& j) {
    const auto it = j.find(FrontendConfig::kHostKeyKey);
    if (it == j.end()) return {};
    if (it->is_array()) return it->get<std::vector<uint8_t>>();
    return {it->get<uint8_t>()};
}

}

void FrontendConfig::OnReady() {
    path_ = cerfcore::GetCerfDir() + kGlobalConfigFileName;
    emu_.Get<cerfcore::ConfigReader>().ReadLoggedJsonFile<json>(path_);
}

json FrontendConfig::Current() const { return LoadJsonObject(QString::fromStdString(path_)); }

std::string FrontendConfig::HostBranch() const {
    return Current().value(kHostBranchKey, std::string(host_branch_table::kKeyless));
}

std::string FrontendConfig::Device() const { return Current().value(kDeviceKey, std::string()); }

bool FrontendConfig::DiscordRichPresence() const { return Current().value(kDiscordRichPresenceKey, false); }

std::vector<uint8_t> FrontendConfig::HostKeyVks() const { return ReadHostKey(Current()); }

int FrontendConfig::DefaultScale() const { return Current().value(kDefaultScaleKey, kDynamicScale); }

std::string FrontendConfig::UpdateChannel() const {
    return Current().value(kUpdateChannelKey, std::string(kUpdateChannelStable));
}

bool FrontendConfig::LastSaveStateMode() const { return Current().value(kLastSaveStateModeKey, false); }

bool FrontendConfig::TutorialFinished() const {
    const json config = Current();
    const auto flag   = config.find(kTutorialFinishedKey);
    return flag != config.end() && *flag == true;
}

bool FrontendConfig::Write(const std::function<void(json&)>& mutate, std::string& error) {
    const bool ok = cerfcore::CfgUpdateJsonFile(path_, mutate, cerfcore::CfgEmptyObject::kWrite, error);
    if (!ok) LOG(Cfg, "FrontendConfig: %s\n", error.c_str());
    return ok;
}

void FrontendConfig::SaveLastSaveStateMode(bool save_state) {
    std::string error;
    Write([save_state](json& j) { j[kLastSaveStateModeKey] = save_state; }, error);
}

}
