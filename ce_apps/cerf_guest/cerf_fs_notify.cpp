#include "cerf_fs_driver.h"

#include <windows.h>
#include <pkfuncs.h>

#define CERF_HT_FIND              8
#define CERF_REGISTER_APISET_TYPE 0x80000000
#define CERF_FS_MAX_WATCH         32

typedef struct CerfWatch {
    HANDLE hEvent;
    HANDLE hNotify;
    BOOL   subtree;
    DWORD  filter;
    BOOL   inUse;
    WCHAR  path[CERF_FS_MAX_LFN + 1];
} CerfWatch;

typedef BOOL   (*PFN_SetEventData)(HANDLE, DWORD);
typedef HANDLE (*PFN_CreateAPISet)(char*, USHORT, const PFNVOID*, const ULONGLONG*);

typedef struct {
    CerfWatch        watch[CERF_FS_MAX_WATCH];
    CRITICAL_SECTION cs;
    HANDLE           hApi;
    BOOL             ready;
    PFN_SetEventData pSetEventData;
} CerfNotifyState;

static CerfNotifyState s_ntf;

static CerfNotifyState* Ntf(void) { return &s_ntf; }

static BOOL CerfNotifyClose(CerfWatch* w) {
    CerfNotifyState* ns = Ntf();
    if (!w) return TRUE;
    EnterCriticalSection(&ns->cs);
    if (w->inUse) {
        if (w->hEvent) CloseHandle(w->hEvent);
        w->hEvent = NULL; w->hNotify = NULL; w->inUse = FALSE;
    }
    LeaveCriticalSection(&ns->cs);
    return TRUE;
}
static BOOL CerfNotifyReset(CerfWatch* w, void* ignored) {
    (void)ignored;
    if (w && w->hEvent) ResetEvent(w->hEvent);
    return TRUE;
}

static const PFNVOID g_notifyMethods[3] = {
    (PFNVOID)CerfNotifyClose, (PFNVOID)NULL, (PFNVOID)CerfNotifyReset,
};

static const DWORD g_notifySig32[3] = { 0x000, 0x000, 0x004 };

void CerfFsNotifyInit(void) {
    CerfNotifyState* ns = Ntf();
    HMODULE core;
    PFN_CreateAPISet pCreateAPISet;
    if (ns->ready) return;
    core = LoadLibraryW(L"coredll.dll");
    if (!core) return;
    ns->pSetEventData = (PFN_SetEventData)GetProcAddressW(core, L"SetEventData");
    if (!ns->pSetEventData) { CERF_LOG("cerf_guest: notify SetEventData absent"); return; }
    pCreateAPISet = (PFN_CreateAPISet)GetProcAddressW(core, L"CreateAPISet");
    if (!pCreateAPISet) return;

    ns->hApi = pCreateAPISet("CFSN", 3, g_notifyMethods, (const ULONGLONG*)g_notifySig32);
    if (!ns->hApi) { CERF_LOG("cerf_guest: notify CreateAPISet FAILED"); return; }

    InitializeCriticalSection(&ns->cs);
    RegisterAPISet(ns->hApi, CERF_HT_FIND | CERF_REGISTER_APISET_TYPE);
    ns->ready = TRUE;
    CERF_LOG("cerf_guest: notify init complete");
}

HANDLE CerfFsFindFirstChangeNotificationW(CerfVol* vol, HANDLE hProc, PCWSTR path,
                                          BOOL subtree, DWORD filter) {
    CerfNotifyState* ns = Ntf();
    int i, n;
    CerfWatch* w = NULL;
    HANDLE hEvent, hNotify;
    (void)vol;
    if (!ns->ready) { SetLastError(ERROR_NOT_SUPPORTED); return INVALID_HANDLE_VALUE; }

    EnterCriticalSection(&ns->cs);
    for (i = 0; i < CERF_FS_MAX_WATCH; ++i)
        if (!ns->watch[i].inUse) { w = &ns->watch[i]; break; }
    if (!w) {
        LeaveCriticalSection(&ns->cs);
        SetLastError(ERROR_TOO_MANY_OPEN_FILES);
        return INVALID_HANDLE_VALUE;
    }
    hEvent = CreateEvent(NULL, TRUE, FALSE, NULL);
    if (!hEvent) { LeaveCriticalSection(&ns->cs); return INVALID_HANDLE_VALUE; }

    n = path ? lstrlenW(path) : 0;
    if (n > CERF_FS_MAX_LFN) n = CERF_FS_MAX_LFN;
    if (n) memcpy(w->path, path, n * sizeof(WCHAR));
    w->path[n] = 0;
    w->hEvent = hEvent; w->subtree = subtree; w->filter = filter;
    w->hNotify = NULL;  w->inUse = TRUE;

    hNotify = CerfFsMakeHandle(ns->hApi, w, hProc);
    if (hNotify == INVALID_HANDLE_VALUE) {
        CloseHandle(hEvent); w->inUse = FALSE;
        LeaveCriticalSection(&ns->cs);
        return INVALID_HANDLE_VALUE;
    }
    w->hNotify = hNotify;
    ns->pSetEventData(hEvent, (DWORD)hNotify);
    LeaveCriticalSection(&ns->cs);
    CERF_LOG_X("cerf_guest: FFCN watch armed hEvent", (DWORD)hEvent);
    return hEvent;
}
