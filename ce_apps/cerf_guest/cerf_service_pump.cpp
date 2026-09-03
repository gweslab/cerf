#include <windows.h>

#include "cerf_service_pump.h"
#include "cerf_debug_log.h"

#include "cerf_tick_profiler.h"
#include "cerf_task_manager_pump.h"
#include "cerf_resize_pump.h"
#include "cerf_shell_watch.h"
#include "cerf_calib_warning_pump.h"

#define CERF_SERVICE_TICK_MS 250u

static DWORD WINAPI CerfServicePumpThread(LPVOID) {
    DWORD n = 0;
    CERF_LOG("cerf_guest: servicepump thread start");
    for (;;) {
        Sleep(CERF_SERVICE_TICK_MS);
        ++n;
        CerfTickProfilerTick();
        if ((n & 1u) == 0) CerfTaskManagerTick();
        if ((n & 3u) == 0) {
            CerfResizeTick();
            CerfShellWatchTick();
            CerfCalibWarningTick();
        }
    }
}

extern "C" void CerfStartServicePump(void) {
    static BOOL started = FALSE;
    HANDLE t;
    if (started) return;
    started = TRUE;
    t = CreateThread(NULL, 0, CerfServicePumpThread, NULL, 0, NULL);
    if (t) CloseHandle(t);
}
