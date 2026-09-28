#include "user_config_writer.h"

#include "cerf_emulator.h"
#include "cerf_paths.h"
#include "config_json.h"
#include "device_config.h"
#include "log.h"

#include <fstream>

REGISTER_SERVICE(UserConfigWriter);

void UserConfigWriter::WriteConfigurableScreenSize(uint32_t width,
                                                   uint32_t height) {
    if (width == 0 || height == 0) return;

    auto& config = emu_.Get<DeviceConfig>();
    const std::string path =
        GetDeviceDir(config.device_name) + "cerf-user.json";

    nlohmann::json j = CfgReadJsonFile(path);
    if (!j.is_object()) j = nlohmann::json::object();
    if (!j.contains("board") || !j["board"].is_object())
        j["board"] = nlohmann::json::object();
    j["board"]["configurable_screen_width"]  = width;
    j["board"]["configurable_screen_height"] = height;

    std::ofstream f(Utf8ToWide(path.c_str()), std::ios::trunc | std::ios::binary);
    if (!f.is_open()) {
        LOG(Cfg, "UserConfigWriter: cannot write '%s'\n", path.c_str());
        return;
    }
    f << j.dump(2) << '\n';

    config.board_configurable_screen_width    = width;
    config.board_configurable_screen_height   = height;
    config.board_configurable_screen_explicit = true;
    LOG(Cfg, "UserConfigWriter: persisted guest resolution %ux%u\n", width,
        height);
}
