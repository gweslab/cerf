#include "emulator_raise.h"

#define NOMINMAX
#include <windows.h>

bool RaiseEmulatorWindow(const RunningStatus& status) {
    const HWND window = reinterpret_cast<HWND>(static_cast<uintptr_t>(status.hwnd));
    if (window == nullptr || !IsWindow(window)) return false;
    if (status.pid != 0) {
        DWORD owner = 0;
        GetWindowThreadProcessId(window, &owner);
        if (owner != status.pid) return false;
    }
    ShowWindow(window, SW_RESTORE);
    SetForegroundWindow(window);
    return true;
}
