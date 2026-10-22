#pragma once

#include <cerfcore/core/service.h>

#include <cstdint>
#include <string>
#include <vector>

namespace cerffrontend {

class FrontendConfig : public cerfcore::Service {
public:
    using cerfcore::Service::Service;

    static constexpr int kDynamicScale = 0;

    void OnReady() override;

    const std::string& Path() const { return path_; }
    const std::string& Device() const { return device_; }
    bool DiscordRichPresence() const { return discord_rich_presence_; }
    const std::vector<uint8_t>& HostKeyVks() const { return host_key_vks_; }
    int DefaultScale() const { return default_scale_; }

    bool LastSaveStateMode() const { return last_save_state_mode_; }
    void SaveLastSaveStateMode(bool save_state);

private:
    std::string          path_;
    std::string          device_;
    bool                 last_save_state_mode_  = false;
    bool                 discord_rich_presence_ = false;
    std::vector<uint8_t> host_key_vks_;
    int                  default_scale_ = kDynamicScale;
};

}
