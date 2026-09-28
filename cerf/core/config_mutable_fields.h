#pragma once

#include "config_json.h"
#include "device_config.h"
#include "share_folder_mount_name.h"

#include <string>

inline void CfgResetMutableFields(DeviceConfig& config) {
    config.board_configurable_screen_width    = kDefaultConfigurableScreenWidth;
    config.board_configurable_screen_height   = kDefaultConfigurableScreenHeight;
    config.board_configurable_screen_explicit = false;
    config.screen_dpi                         = 0;
    config.board_configurable_screen_bpp      = 0;
    config.guest_additions_color_scheme.clear();
    config.guest_additions_font_size = 0;
    config.guest_additions_font_size_set = false;
    config.share_folder.clear();
    config.share_folder_mount_point.clear();
}

inline void CfgLoadMutableScreenFields(const nlohmann::json& board,
                                       DeviceConfig& config,
                                       const std::string& path) {
    if (board.contains("configurable_screen_width")) {
        const int n = CfgReadOptInt(board, "configurable_screen_width", path,
                                    "board");
        if (n < 1)
            CfgFatal(path, "board.configurable_screen_width must be >= 1");
        config.board_configurable_screen_width    = (uint32_t)n;
        config.board_configurable_screen_explicit = true;
    }
    if (board.contains("configurable_screen_height")) {
        const int n = CfgReadOptInt(board, "configurable_screen_height", path,
                                    "board");
        if (n < 1)
            CfgFatal(path, "board.configurable_screen_height must be >= 1");
        config.board_configurable_screen_height   = (uint32_t)n;
        config.board_configurable_screen_explicit = true;
    }
    if (board.contains("configurable_screen_dpi")) {
        const int n = CfgReadOptInt(board, "configurable_screen_dpi", path,
                                    "board");
        if (n < 1)
            CfgFatal(path, "board.configurable_screen_dpi must be >= 1");
        config.screen_dpi = (uint32_t)n;
    }
    if (board.contains("configurable_screen_bpp")) {
        const int n = CfgReadOptInt(board, "configurable_screen_bpp", path,
                                    "board");
        if (n < 1)
            CfgFatal(path, "board.configurable_screen_bpp must be >= 1");
        config.board_configurable_screen_bpp = (uint32_t)n;
    }
}

inline void CfgLoadShareFolder(const nlohmann::json& ga, DeviceConfig& config,
                               const std::string& path) {
    if (!ga.contains("share_folder")) return;
    const auto& v = ga["share_folder"];
    if (v.is_string())
        config.share_folder = v.get<std::string>();
    else if (!v.is_null())
        CfgFatal(path, "'guest_additions.share_folder' must be a string (or null)");
}

inline void CfgLoadShareFolderMountPoint(const nlohmann::json& ga,
                                         DeviceConfig& config,
                                         const std::string& path) {
    if (!ga.contains("shared_folder_mount_point")) return;
    const auto& v = ga["shared_folder_mount_point"];
    if (v.is_null()) return;
    if (!v.is_string() || !IsValidShareFolderMountName(v.get<std::string>()))
        CfgFatal(path, "'guest_additions.shared_folder_mount_point' must be a "
                       "valid mount point name (or null)");
    config.share_folder_mount_point = v.get<std::string>();
}

inline void CfgLoadColorScheme(const nlohmann::json& ga, DeviceConfig& config,
                               const std::string& path) {
    if (!ga.contains("override_color_scheme")) return;
    const auto& cs = ga["override_color_scheme"];
    if (cs.is_string())
        config.guest_additions_color_scheme = cs.get<std::string>();
    else if (!cs.is_null())
        CfgFatal(path,
                 "'guest_additions.override_color_scheme' must be a string "
                 "(or null)");
}

inline void CfgLoadGaFontSize(const nlohmann::json& ga, DeviceConfig& config,
                              const std::string& path) {
    if (!ga.contains("override_font_size")) return;
    if (ga["override_font_size"].is_null()) return;
    config.guest_additions_font_size =
        (int32_t)CfgReadOptInt(ga, "override_font_size", path,
                               "guest_additions");
    config.guest_additions_font_size_set = true;
}

inline void CfgLoadMutableFields(const nlohmann::json& root,
                                 DeviceConfig& config,
                                 const std::string& path) {
    if (root.contains("board")) {
        const auto& b = root["board"];
        if (!b.is_object()) CfgFatal(path, "'board' must be an object");
        CfgLoadMutableScreenFields(b, config, path);
    }
    if (root.contains("guest_additions")) {
        const auto& ga = root["guest_additions"];
        if (ga.is_object()) {
            CfgLoadColorScheme(ga, config, path);
            CfgLoadGaFontSize(ga, config, path);
            CfgLoadShareFolder(ga, config, path);
            CfgLoadShareFolderMountPoint(ga, config, path);
        }
    }
}
