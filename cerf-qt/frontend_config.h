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
    const std::string& HostBranch() const { return host_branch_; }
    const std::string& Device() const { return device_; }
    bool DiscordRichPresence() const { return discord_rich_presence_; }
    const std::vector<uint8_t>& HostKeyVks() const { return host_key_vks_; }
    int DefaultScale() const { return default_scale_; }
    const std::string& UpdateChannel() const { return update_channel_; }

    bool LastSaveStateMode() const { return last_save_state_mode_; }
    void SaveLastSaveStateMode(bool save_state);

    bool Write(const std::function<void(nlohmann::ordered_json&)>& mutate, std::string& error);

private:
    void Parse(const nlohmann::ordered_json& j);

    std::string          path_;
    std::string          host_branch_ = host_branch_table::kKeyless;
    std::string          device_;
    bool                 last_save_state_mode_  = false;
    bool                 discord_rich_presence_ = false;
    std::vector<uint8_t> host_key_vks_;
    int                  default_scale_  = kDynamicScale;
    std::string          update_channel_ = kUpdateChannelStable;
};

}
