#include "cerf_toolhelp.h"
#include "cerf_debug_log.h"

#define CERF_TH_MAX_PROC 8

typedef HANDLE (WINAPI *PFN_CreateToolhelp32Snapshot)(DWORD, DWORD);
typedef BOOL   (WINAPI *PFN_CloseToolhelp32Snapshot)(HANDLE);
typedef BOOL   (WINAPI *PFN_Process32First)(HANDLE, LPPROCESSENTRY32);
typedef BOOL   (WINAPI *PFN_Process32Next)(HANDLE, LPPROCESSENTRY32);

typedef struct {
    DWORD                        pid;
    PFN_CreateToolhelp32Snapshot create_snap;
    PFN_CloseToolhelp32Snapshot  close_snap;
    PFN_Process32First           proc_first;
    PFN_Process32Next            proc_next;
} CerfToolhelpSlot;

static CerfToolhelpSlot s_th_slot[CERF_TH_MAX_PROC];
static LONG             s_th_slot_next = 0;

static CerfToolhelpSlot* CerfToolhelpFind(void) {
    DWORD pid = GetCurrentProcessId();
    int i;
    for (i = 0; i < CERF_TH_MAX_PROC; ++i)
        if (s_th_slot[i].pid == pid) return &s_th_slot[i];
    return NULL;
}

static CerfToolhelpSlot* CerfToolhelpResolve(void) {
    CerfToolhelpSlot* slot = CerfToolhelpFind();
    HMODULE h;
    LONG    idx;
    if (slot) return slot;

    idx = InterlockedIncrement(&s_th_slot_next) - 1;
    if (idx < 0 || idx >= CERF_TH_MAX_PROC) {
        CERF_LOG("cerf_guest: toolhelp no free process slot");
        return NULL;
    }
    slot = &s_th_slot[idx];

    h = LoadLibraryW(L"toolhelp.dll");
    if (h) {
        slot->create_snap = (PFN_CreateToolhelp32Snapshot)
            GetProcAddressW(h, L"CreateToolhelp32Snapshot");
        slot->close_snap = (PFN_CloseToolhelp32Snapshot)
            GetProcAddressW(h, L"CloseToolhelp32Snapshot");
        slot->proc_first = (PFN_Process32First)GetProcAddressW(h, L"Process32First");
        slot->proc_next  = (PFN_Process32Next)GetProcAddressW(h, L"Process32Next");
        if (!slot->create_snap || !slot->close_snap ||
            !slot->proc_first || !slot->proc_next) {
            CERF_LOG("cerf_guest: toolhelp exports incomplete");
            slot->create_snap = NULL;
        }
    } else {
        CERF_LOG("cerf_guest: toolhelp.dll missing");
    }

    slot->pid = GetCurrentProcessId();
    return slot;
}

extern "C" BOOL CerfToolhelpReady(void) {
    CerfToolhelpSlot* slot = CerfToolhelpResolve();
    return slot && slot->create_snap != NULL;
}

extern "C" HANDLE CerfToolhelpSnapshotProcesses(void) {
    CerfToolhelpSlot* slot = CerfToolhelpResolve();
    if (!slot || !slot->create_snap) return INVALID_HANDLE_VALUE;
    return slot->create_snap(TH32CS_SNAPPROCESS, 0);
}

extern "C" BOOL CerfToolhelpProcessFirst(HANDLE snap, LPPROCESSENTRY32 pe) {
    CerfToolhelpSlot* slot = CerfToolhelpFind();
    if (!slot || !slot->proc_first) return FALSE;
    return slot->proc_first(snap, pe);
}

extern "C" BOOL CerfToolhelpProcessNext(HANDLE snap, LPPROCESSENTRY32 pe) {
    CerfToolhelpSlot* slot = CerfToolhelpFind();
    if (!slot || !slot->proc_next) return FALSE;
    return slot->proc_next(snap, pe);
}

extern "C" void CerfToolhelpCloseSnapshot(HANDLE snap) {
    CerfToolhelpSlot* slot = CerfToolhelpFind();
    if (slot && slot->close_snap) slot->close_snap(snap);
}
