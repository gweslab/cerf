#include "host_power.h"

#define NOMINMAX
#include <windows.h>

#include <powrprof.h>

namespace cerffrontend::host_power {

namespace {

constexpr wchar_t kShutdownPrivilege[] = L"SeShutdownPrivilege";

bool EnableShutdownPrivilege(uint32_t& error_code) {
    HANDLE token = nullptr;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &token)) {
        error_code = GetLastError();
        return false;
    }
    TOKEN_PRIVILEGES privileges{};
    privileges.PrivilegeCount           = 1;
    privileges.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    const bool adjusted =
        LookupPrivilegeValueW(nullptr, kShutdownPrivilege, &privileges.Privileges[0].Luid) &&
        AdjustTokenPrivileges(token, FALSE, &privileges, 0, nullptr, nullptr);
    error_code = GetLastError();
    CloseHandle(token);
    return adjusted && error_code == ERROR_SUCCESS;
}

bool SuspendNow(uint32_t& error_code) {
    if (!EnableShutdownPrivilege(error_code)) return false;
    if (SetSuspendState(FALSE, FALSE, FALSE)) return true;
    error_code = GetLastError();
    return false;
}

}

SuspendCall Suspend() { return &SuspendNow; }

}
