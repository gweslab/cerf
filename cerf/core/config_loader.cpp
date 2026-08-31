#define _CRT_SECURE_NO_WARNINGS
#include "config_loader.h"
#include "cerf_emulator.h"
#include "config_json.h"
#include "config_mutable_fields.h"
#include "main_config.h"
#include "log.h"
#include "cerf_paths.h"
#include <nlohmann/json.hpp>
#include <fstream>
#include <cstring>
#include <cstdio>
#include <cstdlib>

using nlohmann::json;

REGISTER_SERVICE(ConfigLoader);

namespace {

void SetMetaString(std::string& field, const json& obj, const char* key,
                   const std::string& path, const std::string& ctx) {
    std::string v = CfgReadOptString(obj, key, path, ctx);
    if (!v.empty()) field = std::move(v);
}

void SetMetaInt(int& field, const json& obj, const char* key,
                const std::string& path, const std::string& ctx) {
    int v = CfgReadOptInt(obj, key, path, ctx);
    if (v) field = v;
}

void LoadMeta(const json& root, DeviceMeta& meta, const std::string& path) {
    if (!root.contains("meta")) return;
    const auto& m = root["meta"];
    if (!m.is_object())
        CfgFatal(path, "'meta' must be an object");

    SetMetaString(meta.name,        m, "name",        path, "meta");
    SetMetaString(meta.device_name, m, "device_name", path, "meta");
    SetMetaInt   (meta.device_year, m, "device_year", path, "meta");

    if (m.contains("os")) {
        const auto& o = m["os"];
        if (!o.is_object())
            CfgFatal(path, "'meta.os' must be an object");
        SetMetaString(meta.os_name,      o, "name",      path, "meta.os");
        SetMetaInt   (meta.os_ver_major, o, "ver_major", path, "meta.os");
        SetMetaInt   (meta.os_ver_minor, o, "ver_minor", path, "meta.os");
    }
}

void LoadBoard(const json& root, DeviceConfig& config, const std::string& path) {
    if (!root.contains("board")) return;
    const auto& b = root["board"];
    if (!b.is_object())
        CfgFatal(path, "'board' must be an object");

    if (b.contains("id"))
        config.board_id = CfgReadOptString(b, "id", path, "board");

    CfgLoadMutableScreenFields(b, config, path);
}

void LoadFeatures(const json& root, DeviceConfig& config, const std::string& path) {
    CfgLoadShareFolder(root, config, path);
    if (root.contains("guest_additions")) {
        const auto& ga = root["guest_additions"];
        if (ga.is_boolean()) {
            config.guest_additions = ga.get<bool>();
        } else if (ga.is_object()) {
            if (ga.contains("enabled")) {
                if (!ga["enabled"].is_boolean())
                    CfgFatal(path, "'guest_additions.enabled' must be a boolean");
                config.guest_additions = ga["enabled"].get<bool>();
            }
            CfgLoadColorScheme(ga, config, path);
            CfgLoadGaFontSize(ga, config, path);
        } else {
            CfgFatal(path, "'guest_additions' must be a boolean or an object");
        }
    }
    if (root.contains("full_screen")) {
        if (!root["full_screen"].is_boolean())
            CfgFatal(path, "'full_screen' must be a boolean");
        config.start_fullscreen = root["full_screen"].get<bool>();
    }
    const char* k = "adopt_guest_additions_resolution_for_host_screen";
    if (root.contains(k)) {
        if (!root[k].is_boolean())
            CfgFatal(path, std::string("'") + k + "' must be a boolean");
        config.adopt_guest_additions_resolution_for_host_screen = root[k].get<bool>();
    }
}

void LoadNetwork(const json& root, DeviceConfig& config, const std::string& path) {
    if (!root.contains("network")) return;
    const auto& n = root["network"];
    if (!n.is_object())
        CfgFatal(path, "'network' must be an object");

    if (n.contains("enabled")) {
        if (!n["enabled"].is_boolean())
            CfgFatal(path, "network.enabled must be a boolean");
        config.network_enabled = n["enabled"].get<bool>();
    }
    if (n.contains("mac")) {
        std::string v = CfgReadOptString(n, "mac", path, "network");
        unsigned b[6] = {};
        int got = std::sscanf(v.c_str(), "%02X:%02X:%02X:%02X:%02X:%02X",
                              &b[0], &b[1], &b[2], &b[3], &b[4], &b[5]);
        if (got != 6)
            CfgFatal(path, "network.mac '" + v + "' must be XX:XX:XX:XX:XX:XX hex");
        config.network_mac = v;
    }
    if (n.contains("mtu")) {
        int mtu = CfgReadOptInt(n, "mtu", path, "network");
        if (mtu < 64 || mtu > 9000)
            CfgFatal(path, "network.mtu out of range (64..9000)");
        config.network_mtu = (uint32_t)mtu;
    }
    if (n.contains("forward_tcp"))
        config.network_forward_tcp = CfgReadOptString(n, "forward_tcp", path, "network");
    if (n.contains("forward_udp"))
        config.network_forward_udp = CfgReadOptString(n, "forward_udp", path, "network");
}

void SplitCommaList(const std::string& v, std::vector<std::string>& out) {
    size_t start = 0;
    while (start <= v.size()) {
        size_t comma = v.find(',', start);
        size_t end   = (comma == std::string::npos) ? v.size() : comma;
        std::string item = v.substr(start, end - start);
        while (!item.empty() && (item.front() == ' ' || item.front() == '\t'))
            item.erase(item.begin());
        while (!item.empty() && (item.back() == ' ' || item.back() == '\t'))
            item.pop_back();
        if (!item.empty()) out.push_back(item);
        if (comma == std::string::npos) break;
        start = comma + 1;
    }
}

void LoadRom(const json& root, DeviceConfig& config, const std::string& path) {
    if (!root.contains("rom")) return;
    const auto& r = root["rom"];
    if (!r.is_object())
        CfgFatal(path, "'rom' must be an object");

    if (r.contains("primary"))
        config.rom_primary = CfgReadOptString(r, "primary", path, "rom");
    if (r.contains("eeprom"))
        config.rom_eeprom = CfgReadOptString(r, "eeprom", path, "rom");
    if (r.contains("recovery"))
        config.rom_recovery = CfgReadOptString(r, "recovery", path, "rom");
    if (r.contains("extensions")) {
        const auto& e = r["extensions"];
        config.rom_extensions.clear();
        if (e.is_string()) {
            SplitCommaList(e.get<std::string>(), config.rom_extensions);
        } else if (e.is_array()) {
            for (const auto& item : e) {
                if (!item.is_string())
                    CfgFatal(path, "rom.extensions[] entries must be strings");
                config.rom_extensions.push_back(item.get<std::string>());
            }
        } else if (!e.is_null()) {
            CfgFatal(path, "rom.extensions must be a string or array of strings");
        }
    }
}

/* "additional_packages": { "compact_flash_cards": [{ "file", "name" }] } -
   every level is optional. */
void LoadAdditionalPackages(const json& root, DeviceConfig& config,
                            const std::string& path) {
    if (!root.contains("additional_packages")) return;
    const auto& p = root["additional_packages"];
    if (p.is_null()) return;
    if (!p.is_object())
        CfgFatal(path, "'additional_packages' must be an object");

    const char* k = "compact_flash_cards";
    if (!p.contains(k)) return;
    const auto& a = p[k];
    if (a.is_null()) return;
    const std::string ctx = std::string("additional_packages.") + k;
    if (!a.is_array())
        CfgFatal(path, "'" + ctx + "' must be an array of "
                    "{ \"file\": ..., \"name\": ... } objects");
    config.bundled_compact_flash_cards.clear();
    for (const auto& e : a) {
        if (!e.is_object())
            CfgFatal(path, ctx + "[] entries must be objects");
        BundledCompactFlashCard card;
        card.file = CfgReadOptString(e, "file", path, ctx);
        card.name = CfgReadOptString(e, "name", path, ctx);
        card.insert_on_launch = CfgReadOptBool(e, "insert_on_launch", path, ctx);
        if (card.file.empty())
            CfgFatal(path, ctx + "[].file is required");
        if (card.name.empty()) card.name = card.file;
        config.bundled_compact_flash_cards.push_back(std::move(card));
    }
}

void LoadGlobalSubstitutions(const json& root, DeviceConfig& config,
                             const std::string& path) {
    const char* k = "video_driver_names_for_guest_additions";
    if (!root.contains(k)) return;
    const auto& a = root[k];
    if (!a.is_array())
        CfgFatal(path, std::string("'") + k + "' must be an array of "
                    "ROM display-driver module names");
    config.guest_additions_victims.clear();
    for (const auto& v : a) {
        if (!v.is_string())
            CfgFatal(path, std::string(k) + "[] must be a string "
                        "(ROM module name)");
        config.guest_additions_victims.push_back(v.get<std::string>());
    }
}

}  // namespace

void ConfigLoader::LoadInto(DeviceConfig& config) {
    const CerfConfig& cli  = emu_.Config();
    const int         argc = emu_.Argc();
    char** const      argv = emu_.Argv();

    std::string device_name;
    const std::string top_path = GetCerfDir() + "cerf.json";
    {
        json j = CfgReadJsonFile(top_path);
        if (!j.is_null()) {
            if (j.contains("device")) {
                if (!j["device"].is_string())
                    CfgFatal(top_path, "'device' must be a string");
                device_name = j["device"].get<std::string>();
            }
            if (j.contains("last_save_state_mode")) {
                if (!j["last_save_state_mode"].is_boolean())
                    CfgFatal(top_path, "'last_save_state_mode' must be a boolean");
                config.last_save_state_mode = j["last_save_state_mode"].get<bool>();
            }
            if (j.contains("discord_rich_presence")) {
                if (!j["discord_rich_presence"].is_boolean())
                    CfgFatal(top_path, "'discord_rich_presence' must be a boolean");
                config.discord_rich_presence = j["discord_rich_presence"].get<bool>();
            }
            LoadGlobalSubstitutions(j, config, top_path);
        }
    }
    if (cli.device_override && cli.device_override[0])
        device_name = cli.device_override;
    if (device_name.empty()) device_name = "cerfos";
    config.device_name = device_name;

    const std::string dev_path = GetDeviceDir(device_name) + "cerf.json";
    json dev = CfgReadJsonFile(dev_path);
    if (dev.is_null()) {
        LOG(Cfg, "No device config: %s (using DeviceConfig defaults)\n", dev_path.c_str());
    } else {
        LOG(Cfg, "Loading device config: %s\n", dev_path.c_str());
        LoadMeta    (dev, config.meta, dev_path);
        LoadBoard   (dev, config,      dev_path);
        LoadNetwork (dev, config,      dev_path);
        LoadRom     (dev, config,      dev_path);
        LoadFeatures(dev, config,      dev_path);
        LoadAdditionalPackages(dev, config, dev_path);
    }

    const std::string user_path = GetDeviceDir(device_name) + "cerf-user.json";
    json user = CfgReadJsonFile(user_path);
    if (!user.is_null()) {
        LOG(Cfg, "Loading user device config: %s\n", user_path.c_str());
        LoadMeta    (user, config.meta, user_path);
        LoadBoard   (user, config,      user_path);
        LoadNetwork (user, config,      user_path);
        LoadRom     (user, config,      user_path);
        LoadFeatures(user, config,      user_path);
        LoadAdditionalPackages(user, config, user_path);
    }

    /* Device-config CLI overrides, applied after cerf.json so the command
       line wins over the json value. */
    for (int i = 1; i < argc; i++) {
        const char* a = argv[i];
        if (strcmp(a, kArgDisableNetwork) == 0) {
            config.network_enabled = false;
        } else if (strncmp(a, kArgBoardId, sizeof(kArgBoardId) - 1) == 0) {
            config.board_id = a + sizeof(kArgBoardId) - 1;
        } else if (strncmp(a, kArgRomPrimary, sizeof(kArgRomPrimary) - 1) == 0) {
            config.rom_primary = a + sizeof(kArgRomPrimary) - 1;
        } else if (strcmp(a, kArgGuestAdditions) == 0) {
            config.guest_additions = true;
        } else if (strncmp(a, kArgGaColorScheme, sizeof(kArgGaColorScheme) - 1) == 0) {
            config.guest_additions_color_scheme = a + sizeof(kArgGaColorScheme) - 1;
        } else if (strncmp(a, kArgGaFontSize, sizeof(kArgGaFontSize) - 1) == 0) {
            config.guest_additions_font_size =
                (int32_t)atoi(a + sizeof(kArgGaFontSize) - 1);
            config.guest_additions_font_size_set = true;
        } else if (strcmp(a, kArgRecovery) == 0) {
            config.boot_in_recovery = true;
        } else if (strncmp(a, kArgScreenWidth, sizeof(kArgScreenWidth) - 1) == 0) {
            int n = atoi(a + sizeof(kArgScreenWidth) - 1);
            if (n < 1) CfgFatal("(command line)", "--screen-width must be >= 1");
            config.board_configurable_screen_width = (uint32_t)n;
            config.board_configurable_screen_explicit = true;
            /* An explicit size is authoritative over the host-screen fit. */
            config.adopt_guest_additions_resolution_for_host_screen = false;
        } else if (strncmp(a, kArgScreenHeight, sizeof(kArgScreenHeight) - 1) == 0) {
            int n = atoi(a + sizeof(kArgScreenHeight) - 1);
            if (n < 1) CfgFatal("(command line)", "--screen-height must be >= 1");
            config.board_configurable_screen_height = (uint32_t)n;
            config.board_configurable_screen_explicit = true;
            config.adopt_guest_additions_resolution_for_host_screen = false;
        } else if (strncmp(a, kArgScreenDpi, sizeof(kArgScreenDpi) - 1) == 0) {
            int n = atoi(a + sizeof(kArgScreenDpi) - 1);
            if (n < 1) CfgFatal("(command line)", "--screen-dpi must be >= 1");
            config.screen_dpi = (uint32_t)n;
        } else if (strncmp(a, kArgScreenBpp, sizeof(kArgScreenBpp) - 1) == 0) {
            int n = atoi(a + sizeof(kArgScreenBpp) - 1);
            if (n < 1) CfgFatal("(command line)", "--screen-bpp must be >= 1");
            config.board_configurable_screen_bpp = (uint32_t)n;
        } else if (strncmp(a, kArgScreenRefreshRate, sizeof(kArgScreenRefreshRate) - 1) == 0) {
            int n = atoi(a + sizeof(kArgScreenRefreshRate) - 1);
            if (n < 1) CfgFatal("(command line)", "--screen-refresh-rate must be >= 1");
            config.screen_refresh_rate = (uint32_t)n;
        } else if (strncmp(a, kArgShareFolder, sizeof(kArgShareFolder) - 1) == 0) {
            config.share_folder = a + sizeof(kArgShareFolder) - 1;
        } else if (strcmp(a, kArgFullScreen) == 0) {
            config.start_fullscreen = true;
        } else if (strcmp(a, kArgGaTickProfiler) == 0) {
            config.ga_tick_profiler = true;
        } else if (strcmp(a, kArgAbout) == 0) {
            config.show_about_instead_of_run = true;
        } else if (strncmp(a, kArgBoot, sizeof(kArgBoot) - 1) == 0) {
            const char* v = a + sizeof(kArgBoot) - 1;
            if      (strcmp(v, "resume") == 0) config.boot_mode = StateBootMode::Resume;
            else if (strcmp(v, "warm")   == 0) config.boot_mode = StateBootMode::Warm;
            else if (strcmp(v, "cold")   == 0) config.boot_mode = StateBootMode::Cold;
            else CfgFatal("(command line)", "--boot must be resume, warm, or cold");
        } else if (strncmp(a, kArgTab, sizeof(kArgTab) - 1) == 0) {
            const char* v = a + sizeof(kArgTab) - 1;
            if      (strcmp(v, "boot") == 0) config.start_tab = CanvasTab::Boot;
            else if (strcmp(v, "hw")   == 0) config.start_tab = CanvasTab::Hw;
            else if (strcmp(v, "fb")   == 0) config.start_tab = CanvasTab::Framebuffer;
            else CfgFatal("(command line)", "--tab must be boot, hw, or fb");
        }
    }
}

void ConfigLoader::SaveLastSaveStateMode(bool save_state) {
    const std::string top_path = GetCerfDir() + "cerf.json";

    json j = CfgReadJsonFile(top_path);   /* preserve every existing key */
    if (!j.is_object()) j = json::object();
    j["last_save_state_mode"] = save_state;

    emu_.Get<DeviceConfig>().last_save_state_mode = save_state;

    std::ofstream f(top_path, std::ios::trunc);
    if (!f.is_open()) {
        LOG(Cfg, "Could not write '%s' to persist last_save_state_mode\n",
            top_path.c_str());
        return;
    }
    f << j.dump(2) << '\n';
}
