#pragma once
#include <cstdint>

struct CerfConfig {
    const char* device_override = nullptr;

    const char* log_file = nullptr;
    bool flush_outputs = false;
    uint64_t no_log_mask = 0;
};

/* Device-config CLI flags. Owned by ConfigLoader, which applies them to
   DeviceConfig after cerf.json loads (so CLI overrides the json value).
   Listed here so ParseCerfArgs can recognize them instead of rejecting
   them as unknown. */
inline constexpr char kArgScreenWidth[]    = "--screen-width=";
inline constexpr char kArgScreenHeight[]   = "--screen-height=";
inline constexpr char kArgDisableNetwork[] = "--disable-network";
inline constexpr char kArgGuestAdditions[] = "--guest-additions";
inline constexpr char kArgRecovery[]       = "--recovery";

bool ParseCerfArgs(int argc, char* argv[], CerfConfig& cfg);
