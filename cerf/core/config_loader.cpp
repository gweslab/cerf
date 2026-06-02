#define _CRT_SECURE_NO_WARNINGS
#include "config_loader.h"
#include "cerf_emulator.h"
#include "main_config.h"
#include "log.h"
#include <nlohmann/json.hpp>
#include <fstream>
#include <cstring>
#include <cstdio>
#include <cstdlib>
#include <windows.h>

using nlohmann::json;

namespace {

[[noreturn]] void Fatal(const std::string& path, const std::string& msg) {
    LOG(Caution, "FATAL: '%s' %s\n", path.c_str(), msg.c_str());
    CerfFatalExit(CERF_FATAL_RUNTIME_ERROR);
}

json ReadJsonFile(const std::string& path) {
    std::ifstream f(path);
    if (!f.is_open()) return json();
    json j;
    try {
        f >> j;
    } catch (const std::exception& e) {
        Fatal(path, std::string("JSON parse error: ") + e.what());
    }
    if (!j.is_object())
        Fatal(path, "top-level value must be a JSON object");
    return j;
}

std::string ReadOptString(const json& obj, const char* key,
                          const std::string& path, const std::string& ctx) {
    if (!obj.contains(key)) return {};
    const auto& v = obj[key];
    if (v.is_null()) return {};
    if (!v.is_string())
        Fatal(path, ctx + "." + key + " must be a string (or null)");
    return v.get<std::string>();
}

int ReadOptInt(const json& obj, const char* key,
               const std::string& path, const std::string& ctx) {
    if (!obj.contains(key)) return 0;
    const auto& v = obj[key];
    if (v.is_null()) return 0;
    if (!v.is_number_integer())
        Fatal(path, ctx + "." + key + " must be an integer");
    return v.get<int>();
}

void LoadMeta(const json& root, DeviceMeta& meta, const std::string& path) {
    if (!root.contains("meta")) return;
    const auto& m = root["meta"];
    if (!m.is_object())
        Fatal(path, "'meta' must be an object");

    meta.device_name = ReadOptString(m, "device_name", path, "meta");
    meta.board_name  = ReadOptString(m, "board_name",  path, "meta");
    meta.soc_family  = ReadOptString(m, "soc_family",  path, "meta");
    meta.device_year = ReadOptInt   (m, "device_year", path, "meta");

    if (m.contains("os")) {
        const auto& o = m["os"];
        if (!o.is_object())
            Fatal(path, "'meta.os' must be an object");
        meta.os_name      = ReadOptString(o, "name",      path, "meta.os");
        meta.os_ver_major = ReadOptInt   (o, "ver_major", path, "meta.os");
        meta.os_ver_minor = ReadOptInt   (o, "ver_minor", path, "meta.os");
    }
}

void LoadBoard(const json& root, DeviceConfig& config, const std::string& path) {
    if (!root.contains("board")) return;
    const auto& b = root["board"];
    if (!b.is_object())
        Fatal(path, "'board' must be an object");

    if (b.contains("configurable_screen_width")) {
        int n = ReadOptInt(b, "configurable_screen_width", path, "board");
        if (n < 1)
            Fatal(path, "board.configurable_screen_width must be >= 1");
        config.board_configurable_screen_width = (uint32_t)n;
    }
    if (b.contains("configurable_screen_height")) {
        int n = ReadOptInt(b, "configurable_screen_height", path, "board");
        if (n < 1)
            Fatal(path, "board.configurable_screen_height must be >= 1");
        config.board_configurable_screen_height = (uint32_t)n;
    }
}

/* Top-level device-feature flags (not board hardware): guest additions and
   whether to size the guest-additions display to the host screen. */
void LoadFeatures(const json& root, DeviceConfig& config, const std::string& path) {
    if (root.contains("guest_additions")) {
        if (!root["guest_additions"].is_boolean())
            Fatal(path, "'guest_additions' must be a boolean");
        config.guest_additions = root["guest_additions"].get<bool>();
    }
    const char* k = "adopt_guest_additions_resolution_for_host_screen";
    if (root.contains(k)) {
        if (!root[k].is_boolean())
            Fatal(path, std::string("'") + k + "' must be a boolean");
        config.adopt_guest_additions_resolution_for_host_screen = root[k].get<bool>();
    }
}

void LoadNetwork(const json& root, DeviceConfig& config, const std::string& path) {
    if (!root.contains("network")) return;
    const auto& n = root["network"];
    if (!n.is_object())
        Fatal(path, "'network' must be an object");

    if (n.contains("enabled")) {
        if (!n["enabled"].is_boolean())
            Fatal(path, "network.enabled must be a boolean");
        config.network_enabled = n["enabled"].get<bool>();
    }
    if (n.contains("mac")) {
        std::string v = ReadOptString(n, "mac", path, "network");
        unsigned b[6] = {};
        int got = std::sscanf(v.c_str(), "%02X:%02X:%02X:%02X:%02X:%02X",
                              &b[0], &b[1], &b[2], &b[3], &b[4], &b[5]);
        if (got != 6)
            Fatal(path, "network.mac '" + v + "' must be XX:XX:XX:XX:XX:XX hex");
        config.network_mac = v;
    }
    if (n.contains("mtu")) {
        int mtu = ReadOptInt(n, "mtu", path, "network");
        if (mtu < 64 || mtu > 9000)
            Fatal(path, "network.mtu out of range (64..9000)");
        config.network_mtu = (uint32_t)mtu;
    }
    if (n.contains("forward_tcp"))
        config.network_forward_tcp = ReadOptString(n, "forward_tcp", path, "network");
    if (n.contains("forward_udp"))
        config.network_forward_udp = ReadOptString(n, "forward_udp", path, "network");
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
        Fatal(path, "'rom' must be an object");

    if (r.contains("primary"))
        config.rom_primary = ReadOptString(r, "primary", path, "rom");
    if (r.contains("recovery"))
        config.rom_recovery = ReadOptString(r, "recovery", path, "rom");
    if (r.contains("extensions")) {
        const auto& e = r["extensions"];
        config.rom_extensions.clear();
        if (e.is_string()) {
            SplitCommaList(e.get<std::string>(), config.rom_extensions);
        } else if (e.is_array()) {
            for (const auto& item : e) {
                if (!item.is_string())
                    Fatal(path, "rom.extensions[] entries must be strings");
                config.rom_extensions.push_back(item.get<std::string>());
            }
        } else if (!e.is_null()) {
            Fatal(path, "rom.extensions must be a string or array of strings");
        }
    }
}

/* Global cerf.json guest-additions substitution map:
   "global_substitutions_inside_rom": { "romModule": "ceAppsDll", ... }. */
void LoadGlobalSubstitutions(const json& root, DeviceConfig& config,
                             const std::string& path) {
    const char* k = "global_substitutions_inside_rom";
    if (!root.contains(k)) return;
    const auto& o = root[k];
    if (!o.is_object())
        Fatal(path, std::string("'") + k + "' must be an object "
                    "{ \"romModule\": \"ceAppsDll\" }");
    config.global_rom_substitutions.clear();
    for (auto it = o.begin(); it != o.end(); ++it) {
        if (!it.value().is_string())
            Fatal(path, std::string(k) + "." + it.key()
                        + " must be a string (ce_apps DLL name)");
        config.global_rom_substitutions.emplace_back(
            it.key(), it.value().get<std::string>());
    }
}

}  // namespace

void ConfigLoader::ApplyAdoptedGuestAdditionsResolution(DeviceConfig& config) {
    const int scr_w = ::GetSystemMetrics(SM_CXSCREEN);
    const int scr_h = ::GetSystemMetrics(SM_CYSCREEN);
    if (scr_w > 10 && scr_h > 40) {
        uint32_t w = (uint32_t)(scr_w - 10);
        uint32_t h = (uint32_t)(scr_h - 40);
        if (w > 3840) w = 3840;   /* clamp wide ultrawide/multimon spans */
        if (h > 2160) h = 2160;
        config.board_configurable_screen_width  = w;
        config.board_configurable_screen_height = h;
    } else {
        LOG(Cfg, "adopt-GA-resolution: host metrics unusable (%dx%d); "
                 "keeping %ux%u\n", scr_w, scr_h,
            config.board_configurable_screen_width,
            config.board_configurable_screen_height);
    }
    LOG(Cfg, "adopt-GA-resolution: host-derived screen=%ux%u\n",
        config.board_configurable_screen_width,
        config.board_configurable_screen_height);
}

void ConfigLoader::Load(const CerfConfig& cli, int argc, char** argv) {
    auto& config = emu_.Get<DeviceConfig>();

    wchar_t cerf_pathw[MAX_PATH];
    ::GetModuleFileNameW(NULL, cerf_pathw, MAX_PATH);
    char cerf_path[MAX_PATH * 3];
    WideCharToMultiByte(CP_UTF8, 0, cerf_pathw, -1, cerf_path, sizeof(cerf_path), NULL, NULL);
    std::string cerf_str(cerf_path);
    size_t last_sep = cerf_str.find_last_of("\\/");
    cerf_dir_ = (last_sep != std::string::npos) ? cerf_str.substr(0, last_sep + 1) : "";

    std::string device_name;
    const std::string top_path = cerf_dir_ + "cerf.json";
    {
        json j = ReadJsonFile(top_path);
        if (!j.is_null()) {
            if (j.contains("device")) {
                if (!j["device"].is_string())
                    Fatal(top_path, "'device' must be a string");
                device_name = j["device"].get<std::string>();
            }
            LoadGlobalSubstitutions(j, config, top_path);
        }
    }
    if (cli.device_override && cli.device_override[0])
        device_name = cli.device_override;
    if (device_name.empty()) device_name = "cerfos";
    config.device_name = device_name;

    const std::string dev_path = cerf_dir_ + "devices/" + device_name + "/cerf.json";
    json dev = ReadJsonFile(dev_path);
    if (dev.is_null()) {
        LOG(Cfg, "No device config: %s (using DeviceConfig defaults)\n", dev_path.c_str());
    } else {
        LOG(Cfg, "Loading device config: %s\n", dev_path.c_str());
        LoadMeta    (dev, config.meta, dev_path);
        LoadBoard   (dev, config,      dev_path);
        LoadNetwork (dev, config,      dev_path);
        LoadRom     (dev, config,      dev_path);
        LoadFeatures(dev, config,      dev_path);
    }

    /* cerf.json may ask the guest-additions display to fill the host screen.
       Applied before the CLI-override loop so an explicit
       --screen-width/--screen-height still wins over the derived size. */
    if (config.adopt_guest_additions_resolution_for_host_screen)
        ApplyAdoptedGuestAdditionsResolution(config);

    /* Device-config CLI overrides, applied after cerf.json so the command
       line wins over the json value. */
    for (int i = 1; i < argc; i++) {
        const char* a = argv[i];
        if (strcmp(a, kArgDisableNetwork) == 0) {
            config.network_enabled = false;
        } else if (strcmp(a, kArgGuestAdditions) == 0) {
            config.guest_additions = true;
        } else if (strcmp(a, kArgRecovery) == 0) {
            config.boot_in_recovery = true;
        } else if (strncmp(a, kArgScreenWidth, sizeof(kArgScreenWidth) - 1) == 0) {
            int n = atoi(a + sizeof(kArgScreenWidth) - 1);
            if (n < 1) Fatal("(command line)", "--screen-width must be >= 1");
            config.board_configurable_screen_width = (uint32_t)n;
        } else if (strncmp(a, kArgScreenHeight, sizeof(kArgScreenHeight) - 1) == 0) {
            int n = atoi(a + sizeof(kArgScreenHeight) - 1);
            if (n < 1) Fatal("(command line)", "--screen-height must be >= 1");
            config.board_configurable_screen_height = (uint32_t)n;
        }
    }
}
