#pragma once

#include <cerfcore/core/device_config_keys.h>

#include <array>

namespace persist_field {

inline constexpr char kNetworkEnabled[]     = "network_enabled";
inline constexpr char kGuestAdditions[]     = "guest_additions";
inline constexpr char kColorScheme[]        = "color_scheme";
inline constexpr const char* kFullScreen    = cerfcore::config_key::kFullScreen;
inline constexpr char kWidth[]              = "width";
inline constexpr char kHeight[]             = "height";
inline constexpr char kDpi[]                = "dpi";
inline constexpr char kFontSize[]           = "font_size";
inline constexpr char kClearType[]          = "cleartype";
inline constexpr const char* kAllowUntrustedApps = cerfcore::config_key::kAllowUntrustedApps;
inline constexpr char kBpp[]                = "bpp";
inline constexpr const char* kShareFolder   = cerfcore::config_key::kShareFolder;
inline constexpr char kMountPoint[]         = "mount_point";
inline constexpr const char* kCpuConfig     = cerfcore::config_key::kCpuConfig;

}

namespace sheet_field {

inline constexpr char kBoardId[]     = "board_id";
inline constexpr const char* kRom     = cerfcore::config_key::kRom;
inline constexpr const char* kStorage = cerfcore::config_key::kStorage;
inline constexpr char kName[]        = "name";

}

namespace sheet_page {

inline constexpr char kBoard[]          = "board";
inline constexpr char kGuestAdditions[] = "guest_additions";
inline constexpr char kDisplay[]        = "display";
inline constexpr char kCpuConfig[]      = "cpu_config";
inline constexpr char kEmulator[]       = "emulator";

}

inline constexpr std::array<const char*, 17> kPersistKeys = {
    persist_field::kNetworkEnabled, persist_field::kGuestAdditions, persist_field::kColorScheme,
    persist_field::kFullScreen,     persist_field::kWidth,          persist_field::kHeight,
    persist_field::kDpi,            persist_field::kFontSize,       persist_field::kClearType,
    persist_field::kAllowUntrustedApps, persist_field::kBpp,        persist_field::kShareFolder,
    persist_field::kMountPoint,     persist_field::kCpuConfig,      cerfcore::config_key::kThrottleMultiplier,
    cerfcore::config_key::kCpuRateMultiplier, cerfcore::config_key::kDoubleTapHelper};

struct ScreenFieldKey {
    const char* field;
    const char* config_key;
};

inline constexpr std::array<ScreenFieldKey, 4> kScreenFieldKeys = {{
    {persist_field::kWidth, cerfcore::config_key::kScreenWidth},
    {persist_field::kHeight, cerfcore::config_key::kScreenHeight},
    {persist_field::kDpi, cerfcore::config_key::kScreenDpi},
    {persist_field::kBpp, cerfcore::config_key::kScreenBpp},
}};
