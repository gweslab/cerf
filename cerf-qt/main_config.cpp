#include "main_config.h"
#include <cerfcore/core/cli_option.h>
#include <cerfcore/core/log.h>
#include <cerfcore/core/run_timeout.h>
#include <cstdlib>
#include <cstring>

namespace cerffrontend {

namespace {

constexpr const char* kDeviceConfigOptions[] = {
    cerfcore::kArgBoardId,     cerfcore::kArgRomPrimary,       cerfcore::kArgScreenWidth,
    cerfcore::kArgScreenHeight, cerfcore::kArgScreenDpi,       cerfcore::kArgScreenBpp,
    cerfcore::kArgScreenRefreshRate, cerfcore::kArgGaShareFolder, cerfcore::kArgBoot,
    cerfcore::kArgTab,         cerfcore::kArgGaColorScheme,    cerfcore::kArgGaFontSize,
    cerfcore::kArgGaAutorun};

constexpr const char* kDeviceConfigFlags[] = {cerfcore::kArgDisableNetwork, cerfcore::kArgGuestAdditions,
                                              cerfcore::kArgFullScreen, cerfcore::kArgNoFocus,
                                              cerfcore::kArgRecovery};

bool IsDeviceConfigArgument(const char* argument) {
    const char* value = nullptr;
    for (const char* option : kDeviceConfigOptions)
        if (cerfcore::ReadCliOption(argument, option, value)) return true;
    for (const char* flag : kDeviceConfigFlags)
        if (strcmp(argument, flag) == 0) return true;
    return false;
}

}

ArgParseResult ParseCerfArgs(int argc, char* argv[], cerfcore::CerfConfig& cfg) {
    for (int i = 1; i < argc; i++) {
        const char* v = nullptr;
        if (cerfcore::ReadCliOption(argv[i], kArgLog, v)) {
            cerfcore::Log::SetEnabled(cerfcore::Log::ParseCategories(v));
        } else if (cerfcore::ReadCliOption(argv[i], "--no-log=", v)) {
            cfg.no_log_mask |= cerfcore::Log::ParseCategories(v);
        } else if (cerfcore::ReadCliOption(argv[i], "--log-file=", v)) {
            cfg.log_file = v;
        } else if (strcmp(argv[i], "--flush-outputs") == 0) {
            cfg.flush_outputs = true;
        } else if (cerfcore::ReadCliOption(argv[i], kArgDevice, v)) {
            cfg.device_override = v;
        } else if (cerfcore::ReadCliOption(argv[i], "--timeout=", v)) {
            char* end = nullptr;
            const long secs = strtol(v, &end, 10);
            if (!end || *end != '\0' || secs <= 0 || secs > 86400) {
                LOG(Caution, "--timeout must be a whole number of seconds in 1..86400 (got '%s')\n", v);
                return ArgParseResult::BadArgument;
            }
            cfg.timeout_seconds = (int)secs;
        } else if (strcmp(argv[i], "--allow-flood") == 0) {
            cerfcore::Log::SetAllowFlood(true);
        } else if (strcmp(argv[i], "--quiet") == 0) {
            cerfcore::Log::SetEnabled(cerfcore::Log::MASK_NONE);
        } else if (strcmp(argv[i], "--help") == 0 || strcmp(argv[i], "-h") == 0) {
            return ArgParseResult::HelpShown;
        } else if (!IsDeviceConfigArgument(argv[i])) {
            LOG(Caution, "Unknown argument: %s (use --help)\n", argv[i]);
            return ArgParseResult::BadArgument;
        }
    }

    if (cfg.no_log_mask) {
        cerfcore::Log::SetEnabled(cerfcore::Log::GetEnabled() & ~cfg.no_log_mask);
    }

    if (cfg.flush_outputs) {
        cerfcore::Log::SetFlush(true);
    }

    if (cfg.log_file) {
        cerfcore::Log::SetFile(cfg.log_file);
    }

    cerfcore::RunTimeout::Start(cfg.timeout_seconds);

    return ArgParseResult::Run;
}

}
