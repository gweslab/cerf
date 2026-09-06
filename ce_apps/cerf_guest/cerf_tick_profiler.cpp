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

static volatile ULONG* s_tp_regs = NULL;

static DWORD CerfTpHostMs(void) {
    return (DWORD)s_tp_regs[CerfVirt::kTickProfHostMs / 4];
}

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

static DWORD CerfTpRatio(DWORD guest_delta, DWORD host_delta) {
    if (host_delta == 0) return CERF_TP_UNITY;
    if (guest_delta > CERF_TP_DELTA_CAP) guest_delta = CERF_TP_DELTA_CAP;
    return (guest_delta * CERF_TP_UNITY) / host_delta;
}

static BOOL  s_tp_started   = FALSE;
static DWORD s_tp_prev      = 0;
static DWORD s_tp_prev_host = 0;
static DWORD s_tp_n         = 0;

extern "C" void CerfTickProfilerTick(void) {
    DWORD now, host, delta, host_delta, ratio;
    DWORD n;

    if (!s_tp_regs) return;

    if (!s_tp_started) {
        s_tp_started   = TRUE;
        s_tp_prev      = GetTickCount();
        s_tp_prev_host = CerfTpHostMs();
        CERF_LOG_X("cerf_guest: tickprof start tick", s_tp_prev);
        CERF_LOG_X("cerf_guest: tickprof start host ms", s_tp_prev_host);
        return;
    }

    {
        now            = GetTickCount();
        host           = CerfTpHostMs();
        delta          = now - s_tp_prev;
        host_delta     = host - s_tp_prev_host;
        s_tp_prev      = now;
        s_tp_prev_host = host;
        ratio          = CerfTpRatio(delta, host_delta);

        s_tp_ring[(DWORD)s_tp_written % CERF_TP_SAMPLES] = ratio;
        s_tp_written++;

        n = ++s_tp_n;
        CERF_LOG_X("cerf_guest: tickprof sample", n);
        CERF_LOG_X("cerf_guest: tickprof tick", now);
        CERF_LOG_X("cerf_guest: tickprof delta ms", delta);
        CERF_LOG_X("cerf_guest: tickprof host delta ms", host_delta);
        CERF_LOG_X("cerf_guest: tickprof ratio per mille", ratio);
    }
}

extern "C" void CerfStartTickProfiler(HMODULE self) {
    static BOOL started = FALSE;
    volatile ULONG* regs;
    ULONG enabled;

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
    if (!enabled) {
        VirtualFree((LPVOID)regs, 0, MEM_RELEASE);
        return;
    }
    s_tp_regs = regs;

    CERF_LOG("cerf_guest: tickprof enabled");
    CerfShellWatchRegister(CerfTickProfilerOnShellIsUp);
}
