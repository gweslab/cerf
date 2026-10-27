#include <windows.h>

#include "cerf_coredll_proc.h"
#include "cerf_gwes_ready.h"
#include "main.h"

/* Windows CE 2.0 Toolkit SDK kfuncs.h:22 - SH_WMGR 17 */
#define CERF_SH_WMGR_CE5 17u
#define CERF_SH_WMGR_CE6 81u

#define CERF_GWES_READY_POLL_MS 10u

typedef BOOL (WINAPI *PFN_IsAPIReady)(DWORD);

static PFN_IsAPIReady s_pIsAPIReady = NULL;

static PFN_IsAPIReady CerfIsApiReadyProc(void) {
    if (!s_pIsAPIReady) s_pIsAPIReady = (PFN_IsAPIReady)CerfCoredllProc(L"IsAPIReady");
    return s_pIsAPIReady;
}

extern "C" DWORD CerfShWmgrApiSet(void) {
    return (g_OsMajor >= 6u) ? CERF_SH_WMGR_CE6 : CERF_SH_WMGR_CE5;
}

extern "C" BOOL CerfIsApiReadyAvailable(void) {
    return CerfIsApiReadyProc() != NULL;
}

extern "C" BOOL CerfGwesApiSetReady(void) {
    PFN_IsAPIReady p = CerfIsApiReadyProc();
    if (!p) return FALSE;
    return p(CerfShWmgrApiSet());
}

extern "C" BOOL CerfWaitGwesApiSet(void) {
    PFN_IsAPIReady p = CerfIsApiReadyProc();
    if (!p) return FALSE;
    while (!p(CerfShWmgrApiSet()))
        Sleep(CERF_GWES_READY_POLL_MS);
    return TRUE;
}
