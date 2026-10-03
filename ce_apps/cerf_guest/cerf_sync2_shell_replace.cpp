#include <windows.h>

#include "cerf_debug_log.h"
#include "cerf_init_table.h"
#include "cerf_registry_customizations.h"
#include "cerf_shell_watch.h"
#include "cerf_sync2_shell_replace.h"
#include "cerf_window_owner.h"

#define CERF_S2_MAX_LAUNCH   48
#define CERF_S2_EXPLORER_ORD 50
#define CERF_S2_HAS_EXPLORER 0x1
#define CERF_S2_SLOT_TAKEN   0x2

typedef DWORD (WINAPI *PFN_GetFileAttributesW)(LPCWSTR);
typedef LONG  (WINAPI *PFN_RegDeleteValueW)(HKEY, LPCWSTR);
typedef int   (WINAPI *PFN_MessageBoxW)(HWND, LPCWSTR, LPCWSTR, UINT);

static const WCHAR* const kSync2Files[] = {
    L"\\Windows\\mishell.exe",
    L"\\Windows\\vca_app.exe",
    L"\\Windows\\desktop.exe",
};

static const WCHAR* const kCe6CoreLaunch[] = {
    L"device.dll",        L"device.exe",
    L"gwes.dll",          L"gwes.exe",
    L"servicesStart.exe", L"services.exe",
    L"explorer.exe",
};

static const WCHAR kExplorer[]       = L"explorer.exe";
static const BYTE  kExplorerDepend[] = { 0x14, 0x00, 0x1E, 0x00 };

static const WCHAR kNoticeKey[]   = L"Software\\CERF";
static const WCHAR kNoticeValue[] = L"Sync2ShellNotice";

typedef struct {
    PFN_GetFileAttributesW gfa;
    PFN_RegDeleteValueW    del;
} CerfSync2Api;

static BOOL CerfSync2Resolve(CerfSync2Api* api) {
    HMODULE core = LoadLibraryW(L"coredll.dll");
    if (!core) return FALSE;
    api->gfa = (PFN_GetFileAttributesW)GetProcAddressW(core, L"GetFileAttributesW");
    api->del = (PFN_RegDeleteValueW)GetProcAddressW(core, L"RegDeleteValueW");
    return api->gfa && api->del;
}

static BOOL CerfSync2Fingerprint(const CerfSync2Api* api) {
    int i;
    for (i = 0; i < (int)(sizeof(kSync2Files) / sizeof(kSync2Files[0])); ++i)
        if (api->gfa(kSync2Files[i]) == 0xFFFFFFFFu) return FALSE;
    return TRUE;
}

static BOOL CerfSync2IsCore(const WCHAR* exe) {
    const WCHAR* base = CerfBasenameW(exe);
    int i;
    for (i = 0; i < (int)(sizeof(kCe6CoreLaunch) / sizeof(kCe6CoreLaunch[0])); ++i)
        if (lstrcmpiW(base, kCe6CoreLaunch[i]) == 0) return TRUE;
    return FALSE;
}

static void CerfSync2RemoveOrdinal(const CerfSync2Api* api, HKEY hk, int ord) {
    WCHAR name[16];
    wsprintfW(name, L"Launch%d", ord);
    CERF_LOG_X("cerf_guest: sync2 init remove ordinal", (DWORD)ord);
    CERF_LOG_X("cerf_guest: sync2 init remove Launch rc", (DWORD)api->del(hk, name));
    wsprintfW(name, L"Depend%d", ord);
    api->del(hk, name);
}

static int CerfSync2CoreFlags(const CerfLaunchEntry* e) {
    int f = 0;
    if (lstrcmpiW(CerfBasenameW(e->exe), kExplorer) == 0) f |= CERF_S2_HAS_EXPLORER;
    if (e->ord == CERF_S2_EXPLORER_ORD)                  f |= CERF_S2_SLOT_TAKEN;
    return f;
}

static BOOL CerfSync2RestoreExplorer(HKEY hk, int flags) {
    if (flags & CERF_S2_HAS_EXPLORER) return FALSE;
    if (flags & CERF_S2_SLOT_TAKEN) {
        CERF_LOG("cerf_guest: sync2 init Launch50 is taken - explorer.exe not restored");
        return FALSE;
    }
    RegSetValueExW(hk, L"Launch50", 0, REG_SZ, (const BYTE*)kExplorer, sizeof(kExplorer));
    RegSetValueExW(hk, L"Depend50", 0, REG_BINARY, kExplorerDepend, sizeof(kExplorerDepend));
    CERF_LOG("cerf_guest: sync2 init Launch50 explorer.exe restored");
    return TRUE;
}

static BOOL CerfSync2StripInit(const CerfSync2Api* api) {
    CerfLaunchEntry tbl[CERF_S2_MAX_LAUNCH];
    HKEY hk;
    BOOL changed = FALSE;
    int  flags = 0;
    int  n = CerfReadInitTable(tbl, CERF_S2_MAX_LAUNCH);
    int  i;

    if (n < 1) return FALSE;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"init", 0, 0, &hk) != ERROR_SUCCESS) return FALSE;
    for (i = 0; i < n; ++i) {
        if (CerfSync2IsCore(tbl[i].exe)) {
            flags |= CerfSync2CoreFlags(&tbl[i]);
        } else {
            CerfSync2RemoveOrdinal(api, hk, tbl[i].ord);
            changed = TRUE;
        }
    }
    if (CerfSync2RestoreExplorer(hk, flags)) changed = TRUE;
    RegCloseKey(hk);
    return changed;
}

static void CerfSync2SetNotice(void) {
    HKEY  hk;
    DWORD disp, one = 1;
    if (RegCreateKeyExW(HKEY_LOCAL_MACHINE, kNoticeKey, 0, NULL, REG_OPTION_NON_VOLATILE,
                        KEY_ALL_ACCESS, NULL, &hk, &disp) != ERROR_SUCCESS)
        return;
    RegSetValueExW(hk, kNoticeValue, 0, REG_DWORD, (const BYTE*)&one, sizeof(one));
    RegCloseKey(hk);
}

static BOOL CerfSync2TakeNotice(const CerfSync2Api* api) {
    HKEY  hk;
    DWORD v = 0, cb = sizeof(v), type = 0;
    BOOL  pending;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, kNoticeKey, 0, 0, &hk) != ERROR_SUCCESS) return FALSE;
    pending = RegQueryValueExW(hk, kNoticeValue, NULL, &type, (LPBYTE)&v, &cb) == ERROR_SUCCESS &&
              type == REG_DWORD && v != 0;
    if (pending) api->del(hk, kNoticeValue);
    RegCloseKey(hk);
    return pending;
}

static DWORD WINAPI CerfSync2NoticeThread(LPVOID) {
    HMODULE core = LoadLibraryW(L"coredll.dll");
    PFN_MessageBoxW mb = core
        ? (PFN_MessageBoxW)GetProcAddressW(core, L"MessageBoxW") : NULL;
    if (!mb) return 0;
    mb(NULL,
       L"Guest Additions removed the Ford SYNC 2 shell from startup. This NAND "
       L"image now boots only into the Windows CE shell.\n\n"
       L"The SYNC 2 shell cannot run under Guest Additions.\n\n"
       L"To get the SYNC 2 shell back, delete nand.img from the device folder "
       L"and flash the SYNC 2 upgrade package (.sec file) again.",
       L"CE Runtime Foundation",
       MB_OK | MB_ICONINFORMATION | MB_SETFOREGROUND | MB_TOPMOST);
    return 0;
}

static void CerfSync2OnShellIsUp(void) {
    HANDLE t = CreateThread(NULL, 0, CerfSync2NoticeThread, NULL, 0, NULL);
    if (t) CloseHandle(t);
}

extern "C" BOOL CerfSync2ReplaceShell(void) {
    CerfSync2Api api;

    if (!CerfSync2Resolve(&api)) return FALSE;
    if (!CerfSync2Fingerprint(&api)) return FALSE;
    CERF_LOG("cerf_guest: sync2 fingerprint matched");

    if (CerfSync2StripInit(&api)) {
        CerfSync2SetNotice();
        CERF_LOG("cerf_guest: sync2 init reduced to the CE6 core set - reset pending");
        return TRUE;
    }
    if (CerfSync2TakeNotice(&api)) {
        CerfFlushRegistry();
        CerfShellWatchRegister(CerfSync2OnShellIsUp);
    }
    return FALSE;
}
