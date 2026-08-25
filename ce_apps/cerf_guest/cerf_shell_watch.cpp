#include <windows.h>
#include <tlhelp32.h>

#include "cerf_regs_map.h"
#include "cerf_shell_watch.h"

#define CERF_SHELLWATCH_MAX_LAUNCH 48
#define CERF_SHELLWATCH_EXE_WCHARS 64
#define CERF_SHELLWATCH_MAX_CB     8
#define CERF_SHELLWATCH_POLL_MS    250u
#define CERF_SHELLWATCH_TIMEOUT_MS 120000u

typedef struct { int ord; WCHAR exe[CERF_SHELLWATCH_EXE_WCHARS]; } CerfLaunchEntry;

typedef HANDLE (WINAPI *PFN_CreateToolhelp32Snapshot)(DWORD, DWORD);
typedef BOOL   (WINAPI *PFN_CloseToolhelp32Snapshot)(HANDLE);
typedef BOOL   (WINAPI *PFN_Process32First)(HANDLE, LPPROCESSENTRY32);
typedef BOOL   (WINAPI *PFN_Process32Next)(HANDLE, LPPROCESSENTRY32);

static PFN_CreateToolhelp32Snapshot s_pfnCreateSnap = NULL;
static PFN_CloseToolhelp32Snapshot  s_pfnCloseSnap  = NULL;
static PFN_Process32First           s_pfnProcFirst  = NULL;
static PFN_Process32Next            s_pfnProcNext   = NULL;

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

static const WCHAR* CerfBasenameW(const WCHAR* p) {
    const WCHAR* b = p;
    for (; *p; ++p)
        if (*p == L'\\' || *p == L'/') b = p + 1;
    return b;
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

static BOOL CerfShellWatchResolveToolhelp(void) {
    HMODULE h = LoadLibraryW(L"toolhelp.dll");
    if (!h) return FALSE;
    s_pfnCreateSnap = (PFN_CreateToolhelp32Snapshot)GetProcAddressW(h, L"CreateToolhelp32Snapshot");
    s_pfnCloseSnap  = (PFN_CloseToolhelp32Snapshot) GetProcAddressW(h, L"CloseToolhelp32Snapshot");
    s_pfnProcFirst  = (PFN_Process32First)          GetProcAddressW(h, L"Process32First");
    s_pfnProcNext   = (PFN_Process32Next)           GetProcAddressW(h, L"Process32Next");
    return s_pfnCreateSnap && s_pfnCloseSnap && s_pfnProcFirst && s_pfnProcNext;
}

static BOOL CerfShellWatchPollOnce(const CerfLaunchEntry* tbl, int n, int gwes_ord) {
    HANDLE snap = s_pfnCreateSnap(TH32CS_SNAPPROCESS, 0);
    PROCESSENTRY32 pe;
    BOOL ok, hit = FALSE;
    if (snap == INVALID_HANDLE_VALUE) return FALSE;
    pe.dwSize = sizeof(pe);
    ok = s_pfnProcFirst(snap, &pe);
    while (ok && !hit) {
        const WCHAR* base = CerfBasenameW(pe.szExeFile);
        int i;
        for (i = 0; i < n; ++i) {
            if (tbl[i].ord > gwes_ord && CerfEqualsCIW(base, tbl[i].exe)) { hit = TRUE; break; }
        }
        pe.dwSize = sizeof(pe);
        ok = s_pfnProcNext(snap, &pe);
    }
    s_pfnCloseSnap(snap);
    return hit;
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

static DWORD WINAPI CerfShellWatchThread(LPVOID) {
    DWORD start, elapsed;
    BOOL  resolved = FALSE;

    if (!CerfShellWatchBuildTargets()) return 0;

    start = GetTickCount();
    for (;;) {
        Sleep(CERF_SHELLWATCH_POLL_MS);
        if (!resolved) {
            resolved = TRUE;
            if (!CerfShellWatchResolveToolhelp()) {
                CERF_LOG("cerf_guest: shellwatch toolhelp unavailable - OnShellIsUp disabled");
                return 0;
            }
        }
        if (CerfShellWatchPollOnce(s_tbl, s_n, s_gwes_ord)) {
            CERF_LOG("cerf_guest: shellwatch shell is up - firing OnShellIsUp");
            CerfShellWatchFireCallbacks();
            return 0;
        }
        elapsed = GetTickCount() - start;
        if (elapsed >= CERF_SHELLWATCH_TIMEOUT_MS) {
            CERF_LOG("cerf_guest: shellwatch 2-min timeout - OnShellIsUp not fired");
            return 0;
        }
    }
}

extern "C" void CerfStartShellWatch(void) {
    static BOOL started = FALSE;
    HANDLE t;
    if (started) return;
    started = TRUE;
    t = CreateThread(NULL, 0, CerfShellWatchThread, NULL, 0, NULL);
    if (t) CloseHandle(t);
}
