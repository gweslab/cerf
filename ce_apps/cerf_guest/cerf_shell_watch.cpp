#include <windows.h>
#include <tlhelp32.h>

#include "cerf_regs_map.h"
#include "cerf_shell_watch.h"
#include "cerf_gwes_ready.h"
#include "cerf_toolhelp.h"
#include "cerf_window_owner.h"

#define CERF_SHELLWATCH_MAX_LAUNCH 48
#define CERF_SHELLWATCH_EXE_WCHARS 64
#define CERF_SHELLWATCH_MAX_CB     8
#define CERF_SHELLWATCH_TIMEOUT_TICKS 120u

typedef struct { int ord; WCHAR exe[CERF_SHELLWATCH_EXE_WCHARS]; } CerfLaunchEntry;

typedef void (*CerfOnShellIsUp)(void);
static CerfOnShellIsUp s_cbs[CERF_SHELLWATCH_MAX_CB];
static int             s_cb_count = 0;

extern "C" void CerfShellWatchRegister(void (*cb)(void)) {
    if (cb && s_cb_count < CERF_SHELLWATCH_MAX_CB) s_cbs[s_cb_count++] = (CerfOnShellIsUp)cb;
}

static void CerfShellWatchFireCallbacks(void) {
    int i;
    for (i = 0; i < s_cb_count; ++i)
        if (s_cbs[i]) s_cbs[i]();
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

static int CerfParseLaunchName(const WCHAR* name, int* ord) {
    const WCHAR* pfx = L"launch";
    const WCHAR* p   = name;
    int v = 0;
    for (; *pfx; ++pfx, ++p) {
        WCHAR c = *p;
        if (c >= L'A' && c <= L'Z') c = (WCHAR)(c + 32);
        if (c != *pfx) return 0;
    }
    if (!(*p >= L'0' && *p <= L'9')) return 0;
    for (; *p >= L'0' && *p <= L'9'; ++p) v = v * 10 + (int)(*p - L'0');
    if (*p != 0) return 0;
    *ord = v;
    return 1;
}

static int CerfReadInitTable(CerfLaunchEntry* tbl, int max) {
    HKEY  hk;
    DWORD idx = 0;
    int   n   = 0;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"init", 0, 0, &hk) != ERROR_SUCCESS)
        return -1;
    for (;;) {
        WCHAR name[CERF_SHELLWATCH_EXE_WCHARS];
        WCHAR data[MAX_PATH];
        DWORD nlen = CERF_SHELLWATCH_EXE_WCHARS;
        DWORD dlen = sizeof(data);
        DWORD type = 0;
        int   ord, i;
        if (RegEnumValueW(hk, idx, name, &nlen, NULL, &type, (LPBYTE)data, &dlen) != ERROR_SUCCESS)
            break;
        idx++;
        if (type != REG_SZ) continue;
        if (!CerfParseLaunchName(name, &ord)) continue;
        if (n >= max) break;
        tbl[n].ord = ord;
        for (i = 0; i < CERF_SHELLWATCH_EXE_WCHARS - 1 && data[i]; ++i)
            tbl[n].exe[i] = data[i];
        tbl[n].exe[i] = 0;
        n++;
    }
    RegCloseKey(hk);
    return n;
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

static CerfLaunchEntry s_tbl[CERF_SHELLWATCH_MAX_LAUNCH];
static int             s_n        = 0;
static int             s_gwes_ord = -1;

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

static BOOL CerfShellWatchBuildTargets(void) {
    int n, gord = -1, targets = 0;
    n = CerfReadInitTable(s_tbl, CERF_SHELLWATCH_MAX_LAUNCH);
    if (n > 0) {
        gord = CerfFindGwesOrd(s_tbl, n);
        if (gord >= 0) targets = CerfCountAfter(s_tbl, n, gord);
    }
    s_n = n;
    s_gwes_ord = gord;
    if (targets > 0) {
        CERF_LOG_X("cerf_guest: shellwatch gwes ordinal", (DWORD)gord);
        CERF_LOG_X("cerf_guest: shellwatch poll targets", (DWORD)targets);
        return TRUE;
    }
    CERF_LOG("cerf_guest: shellwatch disabled - no gwes anchor or no post-gwes targets in HKLM\\init");
    return FALSE;
}

static BOOL  s_sw_dead      = FALSE;
static BOOL  s_sw_built     = FALSE;
static BOOL  s_sw_by_window = FALSE;
static DWORD s_sw_ticks     = 0;

extern "C" void CerfShellWatchTick(void) {
    if (s_sw_dead) return;

    if (!s_sw_built) {
        s_sw_built = TRUE;
        if (!CerfShellWatchBuildTargets()) {
            s_sw_dead = TRUE;
            return;
        }
        if (!CerfToolhelpReady()) {
            s_sw_by_window = TRUE;
            CERF_LOG("cerf_guest: shellwatch no toolhelp - polling window owners");
        }
    }

    if (s_sw_by_window ? CerfShellWatchPollWindows(s_tbl, s_n, s_gwes_ord)
                       : CerfShellWatchPollOnce(s_tbl, s_n, s_gwes_ord)) {
        CERF_LOG("cerf_guest: shellwatch shell is up - firing OnShellIsUp");
        s_sw_dead = TRUE;
        CerfShellWatchFireCallbacks();
        return;
    }

    if (++s_sw_ticks >= CERF_SHELLWATCH_TIMEOUT_TICKS) {
        CERF_LOG("cerf_guest: shellwatch 2-min timeout - OnShellIsUp not fired");
        s_sw_dead = TRUE;
    }
}
