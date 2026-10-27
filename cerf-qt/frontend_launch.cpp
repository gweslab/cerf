#include "frontend_launch.h"

#include <cerfcore/core/cerf_emulator.h>
#include <cerfcore/core/log.h>
#include "cli_usage.h"
#include "main_config.h"
#include "product_links.h"
#include "version.h"

namespace cerffrontend {

std::optional<int> FrontendLaunch::ParseArgs(int argc, char** argv, cerfcore::CerfConfig& cfg) {
    switch (ParseCerfArgs(argc, argv, cfg)) {
        case ArgParseResult::Run:         return std::nullopt;
        case ArgParseResult::BadArgument: return cerfcore::CERF_FATAL_USER_ERROR;
        case ArgParseResult::HelpShown:   break;
    }
    cerfcore::CerfEmulator help(cfg, argc, argv);
    help.CreateAllServices();
    help.Get<CliUsage>().Print(argv[0]);
    return cerfcore::CERF_FATAL_NORMAL_EXIT;
}

void FrontendLaunch::OpenLog(cerfcore::Log::Cat channel, const char* file_name) {
    cerfcore::Log::InitDefaultLogFile(file_name);
    cerfcore::Log::InstallCrashHandler();
    if (!cerfcore::Log::IsEnabled(channel)) return;
    cerfcore::Log::Print(channel, "== %s %s ==\n", kProductName, CERF_VERSION_DISPLAY_STR);
    cerfcore::Log::Print(channel, "compiled at: %s %s\n", __DATE__, __TIME__);
}

}
