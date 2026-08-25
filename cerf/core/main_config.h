#pragma once
#include <cstdint>

struct CerfConfig {
    const char* device_override = nullptr;

    const char* log_file = nullptr;
    bool flush_outputs = false;
    uint64_t no_log_mask = 0;
    int timeout_seconds = 0;
};

/* Device-config CLI flags. Owned by ConfigLoader, which applies them to
   DeviceConfig after cerf.json loads (so CLI overrides the json value).
   Listed here so ParseCerfArgs can recognize them instead of rejecting
   them as unknown. */
inline constexpr char kArgBoardId[]        = "--board-id=";
inline constexpr char kArgRomPrimary[]     = "--rom-primary=";
inline constexpr char kArgScreenWidth[]    = "--screen-width=";
inline constexpr char kArgScreenHeight[]   = "--screen-height=";
inline constexpr char kArgScreenDpi[]      = "--screen-dpi=";
inline constexpr char kArgScreenBpp[]      = "--screen-bpp=";
inline constexpr char kArgScreenRefreshRate[] = "--screen-refresh-rate=";
inline constexpr char kArgDisableNetwork[] = "--disable-network";
inline constexpr char kArgGuestAdditions[] = "--guest-additions";
inline constexpr char kArgGaColorScheme[]  = "--ga-color-scheme=";
inline constexpr char kArgGaTickProfiler[] = "--ga-tick-profiler";
inline constexpr char kArgRecovery[]       = "--recovery";
inline constexpr char kArgShareFolder[]    = "--share-folder=";
inline constexpr char kArgBoot[]           = "--boot=";
inline constexpr char kArgTab[]            = "--tab=";
inline constexpr char kArgFullScreen[]     = "--full-screen";
inline constexpr char kArgAbout[]          = "--about";

enum class ArgParseResult {
    Run,
    HelpShown,
    BadArgument,
};

ArgParseResult ParseCerfArgs(int argc, char* argv[], CerfConfig& cfg);
