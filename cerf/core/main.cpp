#include "cli_usage.h"
#include "log.h"
#include "main_config.h"
#include "cerf_emulator.h"
#include "host_diagnostics.h"
#include "../version.h"

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#include <timeapi.h>

#include "string_utils.h"

#include <string>
#include <vector>

int wmain(int argc, wchar_t* wargv[]) {
    std::vector<std::string> utf8_args;
    utf8_args.reserve(argc);
    for (int i = 0; i < argc; ++i) utf8_args.push_back(WideToUtf8(wargv[i]));
    std::vector<char*> argv_ptrs;
    argv_ptrs.reserve(argc + 1);
    for (std::string& a : utf8_args) argv_ptrs.push_back(a.data());
    argv_ptrs.push_back(nullptr);
    char** const argv = argv_ptrs.data();

    CerfConfig cfg;
    switch (ParseCerfArgs(argc, argv, cfg)) {
        case ArgParseResult::Run:         break;
        case ArgParseResult::BadArgument: return CERF_FATAL_USER_ERROR;
        case ArgParseResult::HelpShown: {
            CerfEmulator help(cfg, argc, argv);
            help.CreateAllServices();
            help.Get<CliUsage>().Print(argv[0]);
            return CERF_FATAL_NORMAL_EXIT;
        }
    }

    /* Without this, sub-ms cv_.wait_for/Sleep round to the 15.625 ms
       Windows default quantum - OST IRQ latency breaks audio + UI. */
    timeBeginPeriod(1);

    /* dolphin-emu Source/Core/Common/Timer.cpp Timer::IncreaseResolution;
       https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-setprocessinformation:
       ControlMask selects both mechanisms, StateMask 0 turns them off -
       "Always honor Timer Resolution Requests" and HighQoS. */
    PROCESS_POWER_THROTTLING_STATE throttling{};
    throttling.Version     = PROCESS_POWER_THROTTLING_CURRENT_VERSION;
    throttling.ControlMask = PROCESS_POWER_THROTTLING_EXECUTION_SPEED |
                             PROCESS_POWER_THROTTLING_IGNORE_TIMER_RESOLUTION;
    throttling.StateMask   = 0;
    SetProcessInformation(GetCurrentProcess(), ProcessPowerThrottling,
                          &throttling, sizeof(throttling));

    Log::InitDefaultLogFile();
    Log::InstallCrashHandler();

    LOG(Cerf, "== CE Runtime Foundation %s ==\n", CERF_VERSION_DISPLAY_STR);
    LOG(Cerf, "main.cpp compiled at: %s %s\n", __DATE__, __TIME__);
    HostDiagnostics::LogReport();

    CerfEmulator emu(cfg, argc, argv);
    emu.Boot();
    emu.WaitForExit();

    Log::Close();
    timeEndPeriod(1);
    return 0;
}
