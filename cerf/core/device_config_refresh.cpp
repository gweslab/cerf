#include "device_config_refresh.h"

#include "cerf_emulator.h"
#include "cerf_paths.h"
#include "config_json.h"
#include "config_mutable_fields.h"
#include "device_config.h"
#include "log.h"

REGISTER_SERVICE(DeviceConfigRefresh);

void DeviceConfigRefresh::RegisterListener(std::function<void()> fn) {
    listeners_.push_back(std::move(fn));
}

void DeviceConfigRefresh::Refresh() {
    auto& config = emu_.Get<DeviceConfig>();
    CfgResetMutableFields(config);

    const std::string dir = GetDeviceDir(config.device_name);
    static const char* const kFiles[] = { "cerf.json", "cerf-user.json" };
    for (const char* name : kFiles) {
        const std::string path = dir + name;
        nlohmann::json j = CfgReadJsonFile(path);
        if (j.is_null()) continue;
        CfgLoadMutableFields(j, config, path);
    }

    LOG(Cfg, "DeviceConfigRefresh: %ux%u dpi=%u bpp=%u font=%d(set=%d) scheme='%s' share='%s'\n",
        config.board_configurable_screen_width,
        config.board_configurable_screen_height, config.screen_dpi,
        config.board_configurable_screen_bpp,
        config.guest_additions_font_size,
        config.guest_additions_font_size_set ? 1 : 0,
        config.guest_additions_color_scheme.c_str(),
        config.share_folder.c_str());

    for (auto& fn : listeners_) fn();
}
