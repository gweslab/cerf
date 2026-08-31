#include <windows.h>
#include <tlhelp32.h>

#include "cerf_debug_log.h"
#include "cerf_shell_watch.h"
#include "cerf_toolhelp.h"
#include "cerf_window_owner.h"

#define CERF_S2_KILL_MS  10000u
#define CERF_S2_POLL_MS    250u

typedef DWORD (WINAPI *PFN_GetFileAttributesW)(LPCWSTR);
typedef int   (WINAPI *PFN_MessageBoxW)(HWND, LPCWSTR, LPCWSTR, UINT);

static const WCHAR* const kSync2Files[] = {
    L"\\Windows\\mishell.exe",
    L"\\Windows\\vca_app.exe",
    L"\\Windows\\desktop.exe",
};

static const WCHAR kSync2Shell[]  = L"mishell.exe";
static const WCHAR kSync2Replace[] = L"\\Windows\\explorer.exe";

static BOOL CerfSync2Fingerprint(PFN_GetFileAttributesW gfa) {
    int i;
    for (i = 0; i < (int)(sizeof(kSync2Files) / sizeof(kSync2Files[0])); ++i) {
        if (gfa(kSync2Files[i]) == 0xFFFFFFFFu) return FALSE;
    }
    return TRUE;
}

static BOOL CerfSync2LaunchReplacement(void) {
    PROCESS_INFORMATION pi;
    if (!CreateProcessW(kSync2Replace, NULL, NULL, NULL, FALSE, 0,
                        NULL, NULL, NULL, &pi)) {
        CERF_LOG_X("cerf_guest: sync2 explorer.exe launch failed", GetLastError());
        return FALSE;
    }
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    CERF_LOG("cerf_guest: sync2 explorer.exe launched");
    return TRUE;
}

static void CerfSync2KillShellOnce(void) {
    PROCESSENTRY32 pe;
    HANDLE snap = CerfToolhelpSnapshotProcesses();
    BOOL   ok;
    if (snap == INVALID_HANDLE_VALUE) return;
    pe.dwSize = sizeof(pe);
    ok = CerfToolhelpProcessFirst(snap, &pe);
    while (ok) {
        if (lstrcmpiW(CerfBasenameW(pe.szExeFile), kSync2Shell) == 0) {
            HANDLE h = OpenProcess(PROCESS_TERMINATE, FALSE, pe.th32ProcessID);
            if (h) {
                CERF_LOG_X("cerf_guest: sync2 terminating mishell.exe pid",
                           pe.th32ProcessID);
                TerminateProcess(h, 0);
                CloseHandle(h);
            }
        }
        pe.dwSize = sizeof(pe);
        ok = CerfToolhelpProcessNext(snap, &pe);
    }
    CerfToolhelpCloseSnapshot(snap);
}

static DWORD WINAPI CerfSync2ShellReplaceThread(LPVOID) {
    HMODULE core = LoadLibraryW(L"coredll.dll");
    PFN_GetFileAttributesW gfa = core
        ? (PFN_GetFileAttributesW)GetProcAddressW(core, L"GetFileAttributesW") : NULL;
    PFN_MessageBoxW mb = core
        ? (PFN_MessageBoxW)GetProcAddressW(core, L"MessageBoxW") : NULL;
    DWORD start;

    if (!gfa) {
        CERF_LOG("cerf_guest: sync2 no GetFileAttributesW - fingerprint skipped");
        return 0;
    }
    if (!CerfSync2Fingerprint(gfa)) return 0;
    CERF_LOG("cerf_guest: sync2 fingerprint matched - replacing the shell");

    if (!CerfSync2LaunchReplacement()) return 0;

    if (!CerfToolhelpReady()) {
        CERF_LOG("cerf_guest: sync2 no toolhelp - mishell.exe left running");
        return 0;
    }
    start = GetTickCount();
    do {
        CerfSync2KillShellOnce();
        Sleep(CERF_S2_POLL_MS);
    } while (GetTickCount() - start < CERF_S2_KILL_MS);

    if (mb) {
        mb(NULL,
           L"The SYNC 2 shell draws only through the OpenVG accelerator, which "
           L"Guest Additions replace. CERF closed it and started Windows "
           L"Explorer instead.",
           L"CE Runtime Foundation",
           MB_OK | MB_ICONINFORMATION | MB_SETFOREGROUND | MB_TOPMOST);
    }
    return 0;
}

static void CerfSync2OnShellIsUp(void) {
    HANDLE t = CreateThread(NULL, 0, CerfSync2ShellReplaceThread, NULL, 0, NULL);
    if (t) CloseHandle(t);
}

extern "C" void CerfStartSync2ShellReplace(void) {
    static BOOL started = FALSE;
    if (started) return;
    started = TRUE;
    CerfShellWatchRegister(CerfSync2OnShellIsUp);
}
