#define NOMINMAX

#include "host_timer_resolution.h"

#include <windows.h>

#include <timeapi.h>

namespace {

using SetProcessInformationFn = BOOL(WINAPI*)(HANDLE, PROCESS_INFORMATION_CLASS, LPVOID, DWORD);

}

HostTimerResolution::HostTimerResolution() {
    timeBeginPeriod(1);
    const auto set_information = reinterpret_cast<SetProcessInformationFn>(
        GetProcAddress(GetModuleHandleW(L"kernel32.dll"), "SetProcessInformation"));
    if (set_information == nullptr) return;
    PROCESS_POWER_THROTTLING_STATE throttling{};
    throttling.Version     = PROCESS_POWER_THROTTLING_CURRENT_VERSION;
    throttling.ControlMask = PROCESS_POWER_THROTTLING_EXECUTION_SPEED | PROCESS_POWER_THROTTLING_IGNORE_TIMER_RESOLUTION;
    throttling.StateMask   = 0;
    set_information(GetCurrentProcess(), ProcessPowerThrottling, &throttling, sizeof(throttling));
}

HostTimerResolution::~HostTimerResolution() { timeEndPeriod(1); }
