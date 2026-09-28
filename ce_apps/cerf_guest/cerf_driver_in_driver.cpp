#include <windows.h>

#include "cerf_driver_in_driver.h"
#include "cerf_fs_driver.h"
#include "cerf_ndis_miniport.h"
#include "main.h"

typedef HANDLE (WINAPI *PFN_ActivateDeviceEx)(LPCWSTR, LPCVOID, DWORD, LPVOID);
typedef HANDLE (WINAPI *PFN_ActivateDevice)(LPCWSTR, DWORD);
typedef HANDLE (WINAPI *PFN_RegisterDevice)(LPCWSTR, DWORD, LPCWSTR, DWORD);

static const wchar_t kDidKeyPath[] = L"Drivers\\CerfDriverInDriver";
static const wchar_t kDidPrefix[]  = L"CDD";

static BOOL CerfWriteDidKey(const wchar_t* dll_name) {
    HKEY key = NULL;
    DWORD disp = 0;
    LONG rc = RegCreateKeyExW(HKEY_LOCAL_MACHINE, kDidKeyPath, 0, NULL,
                              REG_OPTION_NON_VOLATILE, KEY_ALL_ACCESS, NULL,
                              &key, &disp);
    if (rc != ERROR_SUCCESS) {
        CERF_LOG_X("cerf_guest: driver-in-driver RegCreateKeyEx failed rc", rc);
        return FALSE;
    }

    DWORD index = 1;
    RegSetValueExW(key, L"Dll", 0, REG_SZ, (const BYTE*)dll_name,
                   (DWORD)((wcslen(dll_name) + 1) * sizeof(wchar_t)));
    RegSetValueExW(key, L"Prefix", 0, REG_SZ, (const BYTE*)kDidPrefix,
                   (DWORD)(sizeof(kDidPrefix)));
    RegSetValueExW(key, L"Index", 0, REG_DWORD, (const BYTE*)&index,
                   sizeof(index));
    RegCloseKey(key);
    return TRUE;
}

static DWORD WINAPI CerfDidWorker(LPVOID unused) {
    (void)unused;

    const wchar_t* dll_name = CerfInjectedModuleName();
    if (!dll_name || !dll_name[0]) {
        CERF_LOG("cerf_guest: driver-in-driver ABORT - own module name unknown");
        return 0;
    }
    CERF_LOG("cerf_guest: driver-in-driver starting");

    if (!CerfWriteDidKey(dll_name)) return 0;

    HMODULE core = LoadLibraryW(L"coredll.dll");
    if (!core) {
        CERF_LOG("cerf_guest: driver-in-driver ABORT - no coredll");
        return 0;
    }

    PFN_ActivateDeviceEx adex =
        (PFN_ActivateDeviceEx)GetProcAddressW(core, L"ActivateDeviceEx");
    if (adex) {
        HANDLE h = adex(kDidKeyPath, NULL, 0, NULL);
        CERF_LOG_X("cerf_guest: driver-in-driver ActivateDeviceEx handle", (DWORD)h);
        return 0;
    }

    PFN_ActivateDevice ad =
        (PFN_ActivateDevice)GetProcAddressW(core, L"ActivateDevice");
    if (ad) {
        HANDLE h = ad(kDidKeyPath, 0);
        CERF_LOG_X("cerf_guest: driver-in-driver ActivateDevice handle", (DWORD)h);
        return 0;
    }

    PFN_RegisterDevice rd =
        (PFN_RegisterDevice)GetProcAddressW(core, L"RegisterDevice");
    if (rd) {
        HANDLE h = rd(kDidPrefix, 1, dll_name, 0);
        CERF_LOG_X("cerf_guest: driver-in-driver RegisterDevice handle", (DWORD)h);
        return 0;
    }

    CERF_LOG("cerf_guest: driver-in-driver ABORT - coredll exports none of "
             "ActivateDeviceEx, ActivateDevice, RegisterDevice");
    return 0;
}

extern "C" void CerfStartDriverInDriver(void) {
    static BOOL started = FALSE;
    if (started) return;
    started = TRUE;
    HANDLE t = CreateThread(NULL, 0, CerfDidWorker, NULL, 0, NULL);
    if (t) CloseHandle(t);
}

#define CDD_LIVE_CONTEXT 0x0CDD0001u

extern "C" DWORD CDD_Init(DWORD dwContext) {
    CERF_LOG_INIT(CERF_LOG_CH_SHARED_FOLDERS);
    (void)dwContext;
    CerfFsAfsInit();
    CerfNdisInstall();
    return CDD_LIVE_CONTEXT;
}

extern "C" BOOL CDD_Deinit(DWORD dwData) {
    CERF_LOG_X("cerf_guest: CDD_Deinit", dwData);
    return TRUE;
}

extern "C" DWORD CDD_Open(DWORD dwData, DWORD dwAccess, DWORD dwShareMode) {
    CERF_LOG_X("cerf_guest: CDD_Open", dwData);
    return CDD_LIVE_CONTEXT;
}

extern "C" BOOL CDD_Close(DWORD dwHandle) {
    return TRUE;
}

extern "C" DWORD CDD_Read(DWORD dwHandle, LPVOID pBuf, DWORD nBytes) {
    return 0;
}

extern "C" DWORD CDD_Write(DWORD dwHandle, LPCVOID pBuf, DWORD nBytes) {
    return 0;
}

extern "C" DWORD CDD_Seek(DWORD dwHandle, LONG amount, WORD type) {
    return (DWORD)-1;
}

extern "C" BOOL CDD_IOControl(DWORD dwHandle, DWORD code, PBYTE pIn,
                              DWORD inLen, PBYTE pOut, DWORD outLen,
                              PDWORD pActualOut) {
    return FALSE;
}
