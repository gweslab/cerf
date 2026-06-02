#include "main_config.h"
#include "log.h"
#include "cli_helpers.h"
#include <cstring>

bool ParseCerfArgs(int argc, char* argv[], CerfConfig& cfg) {
    for (int i = 1; i < argc; i++) {
        if (strncmp(argv[i], "--log=", 6) == 0) {
            Log::SetEnabled(Log::ParseCategories(argv[i] + 6));
        } else if (strncmp(argv[i], "--no-log=", 9) == 0) {
            cfg.no_log_mask |= Log::ParseCategories(argv[i] + 9);
        } else if (strncmp(argv[i], "--log-file=", 11) == 0) {
            cfg.log_file = argv[i] + 11;
        } else if (strcmp(argv[i], "--flush-outputs") == 0) {
            cfg.flush_outputs = true;
        } else if (strncmp(argv[i], "--device=", 9) == 0) {
            cfg.device_override = argv[i] + 9;
        } else if (strcmp(argv[i], "--allow-flood") == 0) {
            Log::SetAllowFlood(true);
        } else if (strncmp(argv[i], kArgScreenWidth, sizeof(kArgScreenWidth) - 1) == 0 ||
                   strncmp(argv[i], kArgScreenHeight, sizeof(kArgScreenHeight) - 1) == 0 ||
                   strcmp(argv[i], kArgDisableNetwork) == 0 ||
                   strcmp(argv[i], kArgGuestAdditions) == 0 ||
                   strcmp(argv[i], kArgRecovery) == 0) {
            /* Device-config overrides — applied to DeviceConfig by
               ConfigLoader after cerf.json loads. Recognized here only so
               they are not rejected as unknown args. */
        } else if (strcmp(argv[i], "--quiet") == 0) {
            Log::SetEnabled(Log::MASK_NONE);
        } else if (strcmp(argv[i], "--help") == 0 || strcmp(argv[i], "-h") == 0) {
            PrintUsage(argv[0]);
            return false;
        } else {
            LOG(Caution, "Unknown argument: %s (use --help)\n", argv[i]);
            return false;
        }
    }

    if (cfg.no_log_mask) {
        Log::SetEnabled(Log::GetEnabled() & ~cfg.no_log_mask);
    }

    if (cfg.flush_outputs) {
        Log::SetFlush(true);
    }

    if (cfg.log_file) {
        Log::SetFile(cfg.log_file);
    }

    return true;
}
