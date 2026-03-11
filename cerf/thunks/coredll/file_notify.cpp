/* File change notification thunks: FindFirstChangeNotification, FindNextChangeNotification */
#include "../win32_thunks.h"
#include "../../log.h"

void Win32Thunks::RegisterFileNotifyHandlers() {
    Thunk("FindFirstChangeNotificationW", 1682, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        std::wstring path = ReadWStringFromEmu(mem, regs[0]);
        std::wstring mapped = MapWinCEPath(path);
        LOG(API, "[API] FindFirstChangeNotificationW('%ls', subtree=%d, filter=0x%X)\n",
            path.c_str(), regs[1], regs[2]);
        HANDLE h = FindFirstChangeNotificationW(mapped.c_str(), regs[1], regs[2]);
        LOG(API, "[API]   -> handle=%p\n", h);
        /* Store raw handle (not wrapped) — same convention as CreateEventW.
           WaitForMultipleObjects uses sign-extension to recover native handles. */
        regs[0] = (uint32_t)(uintptr_t)h;
        return true;
    });
    Thunk("FindNextChangeNotification", 1683, [](uint32_t* regs, EmulatedMemory&) -> bool {
        HANDLE h = (HANDLE)(intptr_t)(int32_t)regs[0];
        BOOL ok = FindNextChangeNotification(h);
        LOG(API, "[API] FindNextChangeNotification(0x%08X) -> %d\n", regs[0], ok);
        regs[0] = ok;
        return true;
    });
}
