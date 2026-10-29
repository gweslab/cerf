#pragma once

#include "host_branch_table.h"

#include <cerfcore/core/service.h>

#include <nlohmann/json_fwd.hpp>

#include <cstdint>
#include <functional>
#include <string>
#include <vector>

namespace cerffrontend {

class FrontendConfig : public cerfcore::Service {
public:
    using cerfcore::Service::Service;

    static constexpr char kDeviceKey[]              = "device";
    static constexpr const char* kHostBranchKey     = host_branch_table::kKey;
    static constexpr const char* kHostKeyKey        = host_branch_table::kHostKeyKey;
    static constexpr char kDefaultScaleKey[]        = "default_scale";
    static constexpr char kUpdateChannelKey[]       = "update_channel";
    static constexpr char kDiscordRichPresenceKey[] = "discord_rich_presence";
    static constexpr char kLastSaveStateModeKey[]   = "last_save_state_mode";
    static constexpr char kTutorialFinishedKey[]    = "tutorial_finished";
    static constexpr int    kDynamicScale            = 0;
    static constexpr int    kOriginalScale           = 1;
    static constexpr size_t kMaxHostKeyLength        = 8;
    static constexpr char kUpdateChannelDisabled[] = "disabled";
    static constexpr char kUpdateChannelStable[]   = "stable";
    static constexpr char kUpdateChannelUnstable[] = "unstable";

    static std::vector<int>         DefaultScaleValues();
    static std::vector<const char*> UpdateChannelValues();

    void OnReady() override;

    const std::string& Path() const { return path_; }
    std::string HostBranch() const;
    std::string Device() const;
    bool DiscordRichPresence() const;
    std::vector<uint8_t> HostKeyVks() const;
    int DefaultScale() const;
    std::string UpdateChannel() const;

    bool LastSaveStateMode() const;
    void SaveLastSaveStateMode(bool save_state);

    bool TutorialFinished() const;

    bool Write(const std::function<void(nlohmann::ordered_json&)>& mutate, std::string& error);

private:
    nlohmann::ordered_json Current() const;

    std::string path_;
};

}
