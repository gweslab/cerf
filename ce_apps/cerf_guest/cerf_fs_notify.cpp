#include "cerf_coredll_proc.h"
#include "cerf_fs_driver.h"

#include <windows.h>
#include <pkfuncs.h>

#define CERF_HT_FIND              8
#define CERF_REGISTER_APISET_TYPE 0x80000000

typedef struct CerfWatch {
    HANDLE hEvent;
    HANDLE hNotify;
    BOOL   subtree;
    DWORD  filter;
    WCHAR  path[CERF_FS_MAX_LFN + 1];
} CerfWatch;

typedef BOOL   (*PFN_SetEventData)(HANDLE, DWORD);

typedef struct {
    HANDLE           hApi;
    BOOL             ready;
    PFN_SetEventData pSetEventData;
} CerfNotifyState;

static CerfNotifyState s_ntf;

static CerfNotifyState* Ntf(void) { return &s_ntf; }

static BOOL CerfNotifyClose(CerfWatch* w) {
    if (!w) return TRUE;
    if (w->hEvent) CloseHandle(w->hEvent);
    LocalFree(w);
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
    PFN_CreateAPISet pCreateAPISet;
    if (ns->ready) return;
    ns->pSetEventData = (PFN_SetEventData)CerfCoredllProc(L"SetEventData");
    if (!ns->pSetEventData) { CERF_LOG("cerf_guest: notify SetEventData absent"); return; }
    pCreateAPISet = (PFN_CreateAPISet)CerfCoredllProc(L"CreateAPISet");
    if (!pCreateAPISet) { CERF_LOG("cerf_guest: notify CreateAPISet unresolved"); return; }

    ns->hApi = pCreateAPISet("CFSN", 3, g_notifyMethods, (const ULONGLONG*)g_notifySig32);
    if (!ns->hApi) { CERF_LOG("cerf_guest: notify CreateAPISet FAILED"); return; }

    RegisterAPISet(ns->hApi, CERF_HT_FIND | CERF_REGISTER_APISET_TYPE);
    ns->ready = TRUE;
    CERF_LOG("cerf_guest: notify init complete");
}

HANDLE CerfFsFindFirstChangeNotificationW(CerfVol* vol, HANDLE hProc, PCWSTR path,
                                          BOOL subtree, DWORD filter) {
    CerfNotifyState* ns = Ntf();
    int n;
    CerfWatch* w;
    HANDLE hEvent, hNotify;
    (void)vol;
    if (!ns->ready) { SetLastError(ERROR_NOT_SUPPORTED); return INVALID_HANDLE_VALUE; }

    w = (CerfWatch*)LocalAlloc(LPTR, sizeof(CerfWatch));
    if (!w) { SetLastError(ERROR_OUTOFMEMORY); return INVALID_HANDLE_VALUE; }
    hEvent = CreateEvent(NULL, TRUE, FALSE, NULL);
    if (!hEvent) { LocalFree(w); return INVALID_HANDLE_VALUE; }

    n = path ? lstrlenW(path) : 0;
    if (n > CERF_FS_MAX_LFN) n = CERF_FS_MAX_LFN;
    if (n) memcpy(w->path, path, n * sizeof(WCHAR));
    w->path[n] = 0;
    w->hEvent = hEvent; w->subtree = subtree; w->filter = filter;

    hNotify = CerfFsMakeHandle(ns->hApi, w, hProc);
    if (hNotify == INVALID_HANDLE_VALUE) {
        CloseHandle(hEvent);
        LocalFree(w);
        return INVALID_HANDLE_VALUE;
    }
    w->hNotify = hNotify;
    ns->pSetEventData(hEvent, (DWORD)hNotify);
    CERF_LOG_X("cerf_guest: FFCN watch armed hEvent", (DWORD)hEvent);
    return hEvent;
}
