#pragma once
#include <cstdint>
#include <string>
#include <utility>
#include <vector>

struct DeviceMeta {
    std::string device_name;
    std::string board_name;
    std::string soc_family;
    std::string os_name;
    int         os_ver_major = 0;
    int         os_ver_minor = 0;
    int         device_year  = 0;
};

struct DeviceConfig {
    std::string device_name;

    DeviceMeta meta;

    uint32_t board_configurable_screen_width  = 800;
    uint32_t board_configurable_screen_height = 600;

    bool        network_enabled = true;
    std::string network_mac     = "02:CE:5F:00:00:01";
    uint32_t    network_mtu     = 1500;
    std::string network_forward_tcp;
    std::string network_forward_udp;

    std::string              rom_primary;
    std::vector<std::string> rom_extensions;
    std::string              rom_recovery;

    bool boot_in_recovery = false;
    bool guest_additions = false;

    /* Guest-additions ROM-module substitutions from the GLOBAL cerf.json
       ("global_substitutions_inside_rom"): {ROM module name -> ce_apps DLL}.
       GuestAdditionsInjector replaces each present ROM module with the named
       CERF-built binary from build/<cfg>/Win32/ce_apps/. */
    std::vector<std::pair<std::string, std::string>> global_rom_substitutions;

    /* When true, ConfigLoader overwrites board_configurable_screen_* with the
       host monitor size (host_w-10 x host_h-40, capped 3840x2160) so a
       guest-additions display fills the host screen. Read from cerf.json. */
    bool adopt_guest_additions_resolution_for_host_screen = false;
};
