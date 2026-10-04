#include <windows.h>
#include <tlhelp32.h>

#include "cerf_regs_map.h"
#include "cerf_shell_watch.h"
#include "cerf_gwes_ready.h"
#include "cerf_init_table.h"
#include "cerf_toolhelp.h"
#include "cerf_window_owner.h"

#define CERF_SHELLWATCH_MAX_LAUNCH 48
#define CERF_SHELLWATCH_MAX_CB     8
#define CERF_SHELLWATCH_TIMEOUT_TICKS 120u

typedef void (*CerfOnShellIsUp)(void);

typedef struct {
    CerfOnShellIsUp cbs[CERF_SHELLWATCH_MAX_CB];
    int             cb_count;
    CerfLaunchEntry tbl[CERF_SHELLWATCH_MAX_LAUNCH];
    int             n;
    int             gwes_ord;
    BOOL            dead;
    BOOL            gwes;
    BOOL            built;
    BOOL            by_window;
    BOOL            up;
    DWORD           ticks;
} CerfSwState;

static CerfSwState s_sw;

static CerfSwState* Sw(void) { return &s_sw; }

extern "C" void CerfShellWatchRegister(void (*cb)(void)) {
    CerfSwState* sw = Sw();
    if (cb && sw->cb_count < CERF_SHELLWATCH_MAX_CB)
        sw->cbs[sw->cb_count++] = (CerfOnShellIsUp)cb;
}

extern "C" BOOL CerfShellWatchIsUp(void) {
    return Sw()->up;
}

static void CerfShellWatchFireCallbacks(CerfSwState* sw) {
    int i;
    sw->up = TRUE;
    for (i = 0; i < sw->cb_count; ++i)
        if (sw->cbs[i]) sw->cbs[i]();
}

static int CerfEqualsCIW(const WCHAR* a, const WCHAR* b) {
    for (; *a && *b; ++a, ++b) {
        WCHAR ca = *a, cb = *b;
        if (ca >= L'A' && ca <= L'Z') ca = (WCHAR)(ca + 32);
        if (cb >= L'A' && cb <= L'Z') cb = (WCHAR)(cb + 32);
        if (ca != cb) return 0;
    }
    return *a == *b;
}

static BOOL CerfShellWatchPollOnce(const CerfLaunchEntry* tbl, int n, int gwes_ord) {
    HANDLE snap = CerfToolhelpSnapshotProcesses();
    PROCESSENTRY32 pe;
    BOOL ok, hit = FALSE;
    if (snap == INVALID_HANDLE_VALUE) return FALSE;
    pe.dwSize = sizeof(pe);
    ok = CerfToolhelpProcessFirst(snap, &pe);
    while (ok && !hit) {
        const WCHAR* base = CerfBasenameW(pe.szExeFile);
        int i;
        for (i = 0; i < n; ++i) {
            if (tbl[i].ord > gwes_ord && CerfEqualsCIW(base, tbl[i].exe)) { hit = TRUE; break; }
        }
        pe.dwSize = sizeof(pe);
        ok = CerfToolhelpProcessNext(snap, &pe);
    }
    CerfToolhelpCloseSnapshot(snap);
    return hit;
}

static BOOL CerfShellWatchPollWindows(const CerfLaunchEntry* tbl, int n, int gwes_ord) {
    HWND w;
    if (!CerfGwesApiSetReady()) return FALSE;
    w = GetForegroundWindow();
    if (w) w = GetWindow(w, GW_HWNDFIRST);
    for (; w; w = GetWindow(w, GW_HWNDNEXT)) {
        int i;
        for (i = 0; i < n; ++i) {
            if (tbl[i].ord <= gwes_ord) continue;
            if (CerfWindowOwnerIs(w, tbl[i].exe)) return TRUE;
        }
    }
    return FALSE;
}

static int CerfIsGwesName(const WCHAR* exe) {
    return CerfEqualsCIW(exe, L"gwes.exe") || CerfEqualsCIW(exe, L"gwes.dll");
}

static int CerfFindGwesOrd(const CerfLaunchEntry* t, int n) {
    int i, ord = -1;
    for (i = 0; i < n; ++i)
        if (CerfIsGwesName(t[i].exe) && t[i].ord > ord) ord = t[i].ord;
    return ord;
}

static int CerfCountAfter(const CerfLaunchEntry* t, int n, int gwes_ord) {
    int i, c = 0;
    for (i = 0; i < n; ++i)
        if (t[i].ord > gwes_ord) c++;
    return c;
}

static BOOL CerfShellWatchBuildTargets(CerfSwState* sw) {
    int n, gord = -1, targets = 0;
    n = CerfReadInitTable(sw->tbl, CERF_SHELLWATCH_MAX_LAUNCH);
    if (n > 0) {
        gord = CerfFindGwesOrd(sw->tbl, n);
        if (gord >= 0) targets = CerfCountAfter(sw->tbl, n, gord);
    }
    sw->n = n;
    sw->gwes_ord = gord;
    if (targets > 0) {
        CERF_LOG_X("cerf_guest: shellwatch gwes ordinal", (DWORD)gord);
        CERF_LOG_X("cerf_guest: shellwatch poll targets", (DWORD)targets);
        return TRUE;
    }
    CERF_LOG("cerf_guest: shellwatch no post-gwes targets in HKLM\\init - shell is up at gwes api ready");
    return FALSE;
}

extern "C" void CerfShellWatchTick(void) {
    CerfSwState* sw = Sw();

    if (sw->dead) return;

    if (!sw->gwes) {
        if (CerfIsApiReadyAvailable() && !CerfGwesApiSetReady()) return;
        sw->gwes = TRUE;
        CERF_LOG("cerf_guest: shellwatch gwes api set ready");
    }

    if (!sw->built) {
        sw->built = TRUE;
        if (!CerfShellWatchBuildTargets(sw)) {
            sw->dead = TRUE;
            CerfShellWatchFireCallbacks(sw);
            return;
        }
        if (!CerfToolhelpReady()) {
            sw->by_window = TRUE;
            CERF_LOG("cerf_guest: shellwatch no toolhelp - polling window owners");
        }
    }

    if (sw->by_window ? CerfShellWatchPollWindows(sw->tbl, sw->n, sw->gwes_ord)
                      : CerfShellWatchPollOnce(sw->tbl, sw->n, sw->gwes_ord)) {
        CERF_LOG("cerf_guest: shellwatch shell is up - firing OnShellIsUp");
        sw->dead = TRUE;
        CerfShellWatchFireCallbacks(sw);
        return;
    }

    if (++sw->ticks >= CERF_SHELLWATCH_TIMEOUT_TICKS) {
        CERF_LOG("cerf_guest: shellwatch 2-min timeout - OnShellIsUp not fired");
        sw->dead = TRUE;
    }
}
