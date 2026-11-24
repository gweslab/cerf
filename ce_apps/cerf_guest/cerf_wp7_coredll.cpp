#include "cerf_wp7_coredll.h"
#include "cerf_coredll_proc.h"
#include "cerf_debug_log.h"

static CerfWp7Coredll g_Wp7Coredll;
static BOOL           g_Wp7CoredllResolved;

const CerfWp7Coredll* CerfWp7Api(void) {
    CerfWp7Coredll* api = &g_Wp7Coredll;
    if (g_Wp7CoredllResolved) return api;
    api->lock_pages        = (PFN_CerfWp7LockPages)CerfCoredllProc(L"LockPages");
    api->create_semaphore  = (PFN_CerfWp7CreateSemaphoreW)CerfCoredllProc(L"CreateSemaphoreW");
    api->release_semaphore = (PFN_CerfWp7ReleaseSemaphore)CerfCoredllProc(L"ReleaseSemaphore");
    api->caller_vm         = (PFN_CerfWp7CallerVm)CerfCoredllProc(L"GetCallerVMProcessId");
    api->virtual_alloc_ex  = (PFN_CerfWp7VirtualAllocEx)CerfCoredllProc(L"VirtualAllocEx");
    api->virtual_copy_ex   = (PFN_CerfWp7VirtualCopyEx)CerfCoredllProc(L"VirtualCopyEx");
    api->virtual_free_ex   = (PFN_CerfWp7VirtualFreeEx)CerfCoredllProc(L"VirtualFreeEx");
    api->chassis_rank      = (PFN_CerfWp7ChassisRank)CerfCoredllProc(L"GetDeviceChassisRank");
    if (!api->lock_pages || !api->create_semaphore || !api->release_semaphore || !api->caller_vm ||
        !api->virtual_alloc_ex || !api->virtual_copy_ex || !api->virtual_free_ex || !api->chassis_rank)
        CERF_FATAL("cerf_guest: WP7 coredll lacks a call the WP7 display contract needs - halting");
    g_Wp7CoredllResolved = TRUE;
    return api;
}
