#include "frontend_config.h"
#include "cerfman/json_file.h"
#include "install_root_files.h"
#include "integer_scales.h"

#include <cerfcore/core/cerf_emulator.h>
#include <cerfcore/core/cerf_paths.h>
#include <cerfcore/core/config_json.h>
#include <cerfcore/core/config_reader.h>
#include <cerfcore/core/log.h>

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
    auto&             reader = emu_.Get<cerfcore::ConfigReader>();
    const std::string root   = cerfcore::GetCerfDir();
    path_                    = root + kGlobalConfigFileName;
    defaults_                = reader.ReadLoggedJsonFile<json>(root + kGlobalDefaultsFileName);
    reader.ReadLoggedJsonFile<json>(path_);
}

json FrontendConfig::Read() const { return FillMissingKeys(LoadJsonObject(QString::fromStdString(path_)), defaults_); }

void FrontendConfig::Assign(json& root, const Key& key, const json& value) const {
    if (!defaults_.contains(key) || defaults_.at(key) != value) {
        root[key] = value;
        return;
    }
    if (!root.contains(key)) return;
    root.at(key.parent_pointer()).erase(key.back());
    for (Key section = key.parent_pointer(); !section.empty() && root.at(section).empty();
         section     = section.parent_pointer())
        root.at(section.parent_pointer()).erase(section.back());
}

std::string FrontendConfig::HostBranch() const { return defaults_.at(kHostBranchKey).get<std::string>(); }

std::vector<uint8_t> FrontendConfig::DefaultHostKeyVks() const { return ReadHostKey(defaults_); }

std::string FrontendConfig::Device() const { return Read().at(kDeviceKey).get<std::string>(); }

bool FrontendConfig::DiscordRichPresence() const { return Read().at(kDiscordRichPresenceKey).get<bool>(); }

std::vector<uint8_t> FrontendConfig::HostKeyVks() const { return ReadHostKey(Read()); }

int FrontendConfig::DefaultScale() const { return Read().at(kDefaultScaleKey).get<int>(); }

std::string FrontendConfig::UpdateChannel() const { return Read().at(kUpdateChannelKey).get<std::string>(); }

bool FrontendConfig::LastSaveStateMode() const { return Read().at(kLastSaveStateModeKey).get<bool>(); }

bool FrontendConfig::TutorialFinished() const { return Read().at(kTutorialFinishedKey) == true; }

bool FrontendConfig::Write(const std::function<void(json&)>& mutate, std::string& error) {
    const bool ok = cerfcore::CfgUpdateJsonFile(path_, mutate, cerfcore::CfgEmptyObject::kWrite, error);
    if (!ok) LOG(Cfg, "FrontendConfig: %s\n", error.c_str());
    return ok;
}

void FrontendConfig::SaveLastSaveStateMode(bool save_state) {
    std::string error;
    Write([&](json& j) { Assign(j, Key() / kLastSaveStateModeKey, save_state); }, error);
}

}
