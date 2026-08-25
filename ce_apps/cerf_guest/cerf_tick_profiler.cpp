#include <windows.h>

#include "cerf_tick_profiler.h"
#include "cerf_tick_profiler_ui.h"
#include "cerf_regs_map.h"
#include "cerf_shell_watch.h"

#include "cerf/peripherals/cerf_virt/cerf_virt_addr_map.h"
#include "cerf/peripherals/cerf_virt/cerf_virt_tick_profiler_regs.h"

#define CERF_TP_DELTA_CAP 4000000u

static DWORD   s_tp_ring[CERF_TP_SAMPLES];
static LONG    s_tp_written = 0;
static HMODULE s_tp_self    = NULL;

extern "C" HMODULE CerfTickProfilerModule(void) {
    return s_tp_self;
}

extern "C" int CerfTickProfilerSnapshot(DWORD* out, int max) {
    LONG written = s_tp_written;
    int  count   = (written > CERF_TP_SAMPLES) ? CERF_TP_SAMPLES : (int)written;
    int  i;
    LONG first;
    if (!out || max <= 0) return 0;
    if (count > max) count = max;
    first = written - count;
    for (i = 0; i < count; ++i)
        out[i] = s_tp_ring[(DWORD)(first + i) % CERF_TP_SAMPLES];
    return count;
}

static DWORD CerfTpRatio(DWORD delta) {
    if (delta > CERF_TP_DELTA_CAP) delta = CERF_TP_DELTA_CAP;
    return (delta * CERF_TP_UNITY) / CERF_TP_SAMPLE_MS;
}

static DWORD WINAPI CerfTickProfilerThread(LPVOID) {
    DWORD prev = GetTickCount();
    DWORD n    = 0;

    CERF_LOG_X("cerf_guest: tickprof start tick", prev);

    for (;;) {
        DWORD now, delta, ratio;

        Sleep(CERF_TP_SAMPLE_MS);

        now   = GetTickCount();
        delta = now - prev;
        prev  = now;
        ratio = CerfTpRatio(delta);

        s_tp_ring[(DWORD)s_tp_written % CERF_TP_SAMPLES] = ratio;
        s_tp_written++;

        ++n;
        CERF_LOG_X("cerf_guest: tickprof sample", n);
        CERF_LOG_X("cerf_guest: tickprof tick", now);
        CERF_LOG_X("cerf_guest: tickprof delta ms", delta);
        CERF_LOG_X("cerf_guest: tickprof ratio per mille", ratio);
    }
}

extern "C" void CerfStartTickProfiler(HMODULE self) {
    static BOOL started = FALSE;
    volatile ULONG* regs;
    ULONG enabled;
    HANDLE t;

    if (started) return;
    started = TRUE;
    s_tp_self = self;

    regs = (volatile ULONG*)CerfMapRegsPage(
        g_CerfVirtBase + CerfVirt::kTickProfilerOffset,
        CerfVirt::kTickProfilerSize);
    if (!regs) {
        CERF_LOG("cerf_guest: tickprof map FAILED");
        return;
    }
    enabled = regs[CerfVirt::kTickProfEnable / 4];
    VirtualFree((LPVOID)regs, 0, MEM_RELEASE);
    if (!enabled) return;

    CERF_LOG("cerf_guest: tickprof enabled");
    CerfShellWatchRegister(CerfTickProfilerOnShellIsUp);

    t = CreateThread(NULL, 0, CerfTickProfilerThread, NULL, 0, NULL);
    if (t) CloseHandle(t);
}
