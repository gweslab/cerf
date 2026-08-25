#pragma once
#include "service.h"
#include <cstdint>
#include <string>
#include <utility>
#include <vector>

struct DeviceMeta {
    std::string name;
    std::string device_name;
    std::string os_name;
    int         os_ver_major = 0;
    int         os_ver_minor = 0;
    int         device_year  = 0;
};

/* One entry of cerf.json "additional_packages.compact_flash_cards": a CF
   image file shipped inside the device directory plus its insert-menu
   display name. */
struct BundledCompactFlashCard {
    std::string file;   /* image filename, relative to the device directory */
    std::string name;   /* display name; menu shows "Insert bundled CF: <name>" */
    bool insert_on_launch = false;
};

struct RomFlashRegion {
    std::string file;
    uint32_t    pa = 0;
};

/* Boot action when a saved state image exists in the device directory
   (--boot=resume|cold|warm). */
enum class StateBootMode {
    Resume,   /* full restore from state.img if present, else cold boot */
    Warm,     /* RAM + flash only (OS reboots) if present, else cold boot */
    Cold,     /* ignore state.img, cold boot */
};

/* The host canvas tabs. The startup / reboot / resume tab (--tab=boot|hw|fb)
   selects one; MemoryVisualizer is a dev-only tab, not a startup choice.
   Defined here (not in HostCanvas) so core config can name it without core
   depending on the host layer; HostCanvas aliases it as HostCanvas::Tab. */
enum class CanvasTab {
    Boot,            /* CERF/OEM logo boot screen */
    Hw,              /* hardware text console (UART / debug output) */
    Framebuffer,     /* live guest framebuffer */
    MemoryVisualizer,/* dev memory visualizer */
};

constexpr uint32_t kDefaultConfigurableScreenWidth  = 800;
constexpr uint32_t kDefaultConfigurableScreenHeight = 600;

struct DeviceConfig : public Service {
    using Service::Service;

    /* Populates every field below from the global + per-device cerf.json and
       the CLI, via ConfigLoader. Lazy: runs on first emu_.Get<DeviceConfig>(). */
    void OnReady() override;

    std::string device_name;

    std::string board_id;

    DeviceMeta meta;

    uint32_t board_configurable_screen_width  = kDefaultConfigurableScreenWidth;
    uint32_t board_configurable_screen_height = kDefaultConfigurableScreenHeight;

    /* Guest-additions display DPI override (logical pixels/inch) from
       --screen-dpi / cerf.json board.configurable_screen_dpi. 0 = no override:
       the guest driver then falls back to the ROM's registry DPI, then 96. */
    uint32_t screen_dpi = 0;

    uint32_t board_configurable_screen_bpp = 0;

    uint32_t screen_refresh_rate = 0;

    /* True when the configurable screen size came from cerf.json
       board.configurable_screen_* or --screen-width/height (not the bare
       default above). The host window uses this to let an explicit size win
       over a board's fixed-LCD preferred window size. */
    bool board_configurable_screen_explicit = false;

    bool        network_enabled = true;
    std::string network_mac     = "02:CE:5F:00:00:01";
    uint32_t    network_mtu     = 1500;
    std::string network_forward_tcp;
    std::string network_forward_udp;

    std::string              rom_primary;
    std::vector<std::string> rom_extensions;
    std::string              rom_recovery;

    /* Optional serial-config EEPROM image (cerf.json rom.eeprom). A board's
       SSP/SPI EEPROM peripheral loads it from the device directory; empty
       when the device has none. */
    std::string              rom_eeprom;

    std::string              rom_flash;

    std::vector<std::string> rom_volumes;

    std::vector<RomFlashRegion> rom_flash_regions;

    /* Optional CF images bundled with the ROM (cerf.json
       "additional_packages.compact_flash_cards"); the CF insert menu offers
       each entry whose file is present in the device directory. */
    std::vector<BundledCompactFlashCard> bundled_compact_flash_cards;

    bool boot_in_recovery = false;
    bool guest_additions = false;
    std::string guest_additions_color_scheme;

    /* Startup tab. Dev builds default to the hardware console so debug output
       shows instantly; production defaults to the boot screen. --tab overrides. */
    CanvasTab start_tab =
#if CERF_DEV_MODE
        CanvasTab::Hw;
#else
        CanvasTab::Boot;
#endif

    /* Dev builds default to cold so iteration never auto-resumes a stale
       image; production resumes a saved state. --boot overrides either. */
    StateBootMode boot_mode =
#if CERF_DEV_MODE
        StateBootMode::Cold;
#else
        StateBootMode::Resume;
#endif

    std::string share_folder;

    /* --full-screen: enter borderless fullscreen (the Right Ctrl+F toggle) right
       after the host window is shown. CLI-only launch preference, default off. */
    bool start_fullscreen = false;

    bool show_about_instead_of_run = false;

    /* Guest-additions victim display-driver module names from the GLOBAL
       cerf.json ("video_driver_names_for_guest_additions"): the ROM modules to
       replace with the injected cerf_guest stub. The cerf_guest / cerf_guest_stub
       binary names are owned by GuestAdditionsBinaries, not cerf.json. */
    std::vector<std::string> guest_additions_victims;

    /* When true, ConfigLoader overwrites board_configurable_screen_* with the
       host monitor size (host_w-10 x host_h-40, capped 3840x2160) so a
       guest-additions display fills the host screen. Read from cerf.json. */
    bool adopt_guest_additions_resolution_for_host_screen = false;

    /* Default state of the shutdown dialog's "Save the state" checkbox. Read
       from the GLOBAL cerf.json top-level "last_save_state_mode"; the dialog's
       "Remember choice" checkbox writes the user's selection back to that file
       via ConfigLoader. Defaults off so a close never auto-saves silently. */
    bool last_save_state_mode = false;

    bool discord_rich_presence = false;
};
