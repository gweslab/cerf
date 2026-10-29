#include "frontend_config.h"
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
    const json j = emu_.Get<cerfcore::ConfigReader>().ReadLoggedJsonFile<json>(path_);
    Parse(j.is_null() ? json::object() : j);
}

void FrontendConfig::Parse(const json& j) {
    host_branch_           = j.value(kHostBranchKey, std::string(host_branch_table::kKeyless));
    device_                = j.value(kDeviceKey, std::string());
    last_save_state_mode_  = j.value(kLastSaveStateModeKey, false);
    discord_rich_presence_ = j.value(kDiscordRichPresenceKey, false);
    host_key_vks_          = ReadHostKey(j);
    default_scale_         = j.value(kDefaultScaleKey, kDynamicScale);
    update_channel_        = j.value(kUpdateChannelKey, std::string(kUpdateChannelStable));
}

bool FrontendConfig::Write(const std::function<void(json&)>& mutate, std::string& error) {
    json       written;
    const bool ok = cerfcore::CfgUpdateJsonFile(
        path_,
        [&](json& j) {
            mutate(j);
            written = j;
        },
        cerfcore::CfgEmptyObject::kWrite, error);
    if (!ok) {
        LOG(Cfg, "FrontendConfig: %s\n", error.c_str());
        return false;
    }
    Parse(written);
    return true;
}

void FrontendConfig::SaveLastSaveStateMode(bool save_state) {
    std::string error;
    Write([save_state](json& j) { j[kLastSaveStateModeKey] = save_state; }, error);
}

}
