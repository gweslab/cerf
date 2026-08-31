#include "main_config.h"
#include "log.h"
#include "cli_usage.h"
#include "run_timeout.h"
#include <cstdlib>
#include <cstring>

ArgParseResult ParseCerfArgs(int argc, char* argv[], CerfConfig& cfg) {
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
        } else if (strncmp(argv[i], "--timeout=", 10) == 0) {
            char* end = nullptr;
            const long secs = strtol(argv[i] + 10, &end, 10);
            if (!end || *end != '\0' || secs <= 0 || secs > 86400) {
                LOG(Caution, "--timeout must be a whole number of seconds in 1..86400 (got '%s')\n", argv[i] + 10);
                return ArgParseResult::BadArgument;
            }
            cfg.timeout_seconds = (int)secs;
        } else if (strcmp(argv[i], "--allow-flood") == 0) {
            Log::SetAllowFlood(true);
        } else if (strncmp(argv[i], kArgBoardId, sizeof(kArgBoardId) - 1) == 0 ||
                   strncmp(argv[i], kArgRomPrimary, sizeof(kArgRomPrimary) - 1) == 0 ||
                   strncmp(argv[i], kArgScreenWidth, sizeof(kArgScreenWidth) - 1) == 0 ||
                   strncmp(argv[i], kArgScreenHeight, sizeof(kArgScreenHeight) - 1) == 0 ||
                   strncmp(argv[i], kArgScreenDpi, sizeof(kArgScreenDpi) - 1) == 0 ||
                   strncmp(argv[i], kArgScreenBpp, sizeof(kArgScreenBpp) - 1) == 0 ||
                   strncmp(argv[i], kArgScreenRefreshRate, sizeof(kArgScreenRefreshRate) - 1) == 0 ||
                   strncmp(argv[i], kArgShareFolder, sizeof(kArgShareFolder) - 1) == 0 ||
                   strncmp(argv[i], kArgBoot, sizeof(kArgBoot) - 1) == 0 ||
                   strncmp(argv[i], kArgTab, sizeof(kArgTab) - 1) == 0 ||
                   strncmp(argv[i], kArgGaColorScheme, sizeof(kArgGaColorScheme) - 1) == 0 ||
                   strncmp(argv[i], kArgGaFontSize, sizeof(kArgGaFontSize) - 1) == 0 ||
                   strcmp(argv[i], kArgDisableNetwork) == 0 ||
                   strcmp(argv[i], kArgGuestAdditions) == 0 ||
                   strcmp(argv[i], kArgFullScreen) == 0 ||
                   strcmp(argv[i], kArgGaTickProfiler) == 0 ||
                   strcmp(argv[i], kArgAbout) == 0 ||
                   strcmp(argv[i], kArgRecovery) == 0) {
            /* Device-config overrides - applied to DeviceConfig by
               ConfigLoader after cerf.json loads. Recognized here only so
               they are not rejected as unknown args. */
        } else if (strcmp(argv[i], "--quiet") == 0) {
            Log::SetEnabled(Log::MASK_NONE);
        } else if (strcmp(argv[i], "--help") == 0 || strcmp(argv[i], "-h") == 0) {
            PrintUsage(argv[0]);
            return ArgParseResult::HelpShown;
        } else {
            LOG(Caution, "Unknown argument: %s (use --help)\n", argv[i]);
            return ArgParseResult::BadArgument;
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

    RunTimeout::Start(cfg.timeout_seconds);

    return ArgParseResult::Run;
}
