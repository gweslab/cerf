#include <windows.h>

#include "cerf_allow_unsigned_apps.h"
#include "cerf_coredll_proc.h"
#include "cerf_os_version.h"
#include "cerf_regs_map.h"
#include "cerf_shell_watch.h"

#include "cerfcore/peripherals/cerf_virt/cerf_virt_addr_map.h"
#include "cerfcore/peripherals/cerf_virt/cerf_virt_fb_regs.h"

typedef struct {
    volatile ULONG* regs;
    BOOL            ready;
    BOOL            dead;
} CerfUnsignedState;

#define CERF_FILE_ATTRIBUTE_INROM 0x00000040u

typedef LONG (WINAPI* PFN_CerfRegFlushKey)(HKEY);

static const WCHAR kLoaderVerifierModule[] = L"\\Windows\\lvmod.dll";

static CerfUnsignedState s_unsigned;

static CerfUnsignedState* Us(void) { return &s_unsigned; }

static void CerfSetTrustDword(const WCHAR* key_path, const WCHAR* name, DWORD value) {
    HKEY  key;
    LONG  rc = RegOpenKeyExW(HKEY_LOCAL_MACHINE, key_path, 0, 0, &key);
    if (rc != ERROR_SUCCESS) return;
    rc = RegSetValueExW(key, name, 0, REG_DWORD, (const BYTE*)&value, sizeof(value));
    RegCloseKey(key);
    CERF_LOG_X("cerf_guest: unsigned-app trust value set rc", (ULONG)rc);
}

static void CerfShadowLoaderVerifier(void) {
    static const BYTE kNotAModule[] = "CERF: loader verifier off";
    DWORD  attrs = GetFileAttributesW(kLoaderVerifierModule);
    DWORD  wrote = 0;
    HANDLE f;
    if (attrs == 0xFFFFFFFFu || !(attrs & CERF_FILE_ATTRIBUTE_INROM)) return;
    f = CreateFileW(kLoaderVerifierModule, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (f == INVALID_HANDLE_VALUE) {
        CERF_LOG_X("cerf_guest: loader verifier shadow create err", GetLastError());
        return;
    }
    WriteFile(f, kNotAModule, sizeof(kNotAModule), &wrote, NULL);
    CloseHandle(f);
    CERF_LOG_X("cerf_guest: loader verifier shadowed, bytes", wrote);
}

static void CerfAllowUnsignedAppsWindowsPhone7(void) {
    PFN_CerfRegFlushKey flush = (PFN_CerfRegFlushKey)CerfCoredllProc(L"RegFlushKey");
    CerfSetTrustDword(L"init\\BootVars", L"RequireCertMod", 0);
    if (flush) flush(HKEY_LOCAL_MACHINE);
    CerfShadowLoaderVerifier();
}

static void CerfAllowUnsignedAppsWindowsMobile(void) {
    CerfSetTrustDword(L"Security\\CertMod", L"AllowUntrustedApps", 1);
    CerfSetTrustDword(L"Security\\Policies\\Policies", L"0000101a", 1);
}

extern "C" void CerfAllowUnsignedAppsTick(void) {
    CerfUnsignedState* u = Us();

    if (u->dead) return;
    if (!CerfShellWatchIsUp()) return;

    if (!u->ready) {
        u->ready = TRUE;
        u->regs = (volatile ULONG*)CerfMapRegsPage(
            g_CerfVirtBase + cerfcore::CerfVirt::kFramebufferRegsOffset,
            cerfcore::CerfVirt::kFramebufferRegsSize);
        if (!u->regs) {
            CERF_LOG("cerf_guest: unsigned-app map FAILED");
            u->dead = TRUE;
            return;
        }
    }

    if (!u->regs[cerfcore::CerfVirt::kFbRegAllowUntrustedApps / 4]) return;
    if (CerfIsWp7())
        CerfAllowUnsignedAppsWindowsPhone7();
    else
        CerfAllowUnsignedAppsWindowsMobile();
    u->dead = TRUE;
}
