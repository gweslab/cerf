#include <windows.h>

#include "cerf_debug_log.h"
#include "cerf_regs_map.h"

#include "cerf/peripherals/cerf_virt/cerf_virt_addr_map.h"
#include "cerf/peripherals/cerf_virt/cerf_virt_color_scheme_regs.h"
#include "cerf/peripherals/cerf_virt/cerf_virt_fb_regs.h"

extern LONG  g_FbSystemFontHeight;
extern ULONG g_FbSystemFontPresent;

typedef LONG (WINAPI *PFN_RegFlushKey)(HKEY);

static const WCHAR* const kCerfFontKeys[] = {
    L"System\\GDI\\SYSFNT",
    L"System\\GWE\\Menu\\BarFnt",
    L"System\\GWE\\Menu\\PopFnt",
    L"System\\GWE\\OOMFnt",
};

static BOOL CerfApplyColorScheme(void) {
    volatile ULONG* csc = (volatile ULONG*)CerfMapRegsPage(
        g_CerfVirtBase + CerfVirt::kColorSchemeOffset, CerfVirt::kColorSchemeSize);
    if (!csc) return FALSE;
    if (csc[CerfVirt::kCscPresent / 4] != CerfVirt::kCscMagic) return FALSE;
    ULONG count = csc[CerfVirt::kCscCount / 4];
    if (count == 0 || count > 64) return FALSE;
    DWORD colors[64];
    ULONG i;
    for (i = 0; i < count; ++i)
        colors[i] = csc[(CerfVirt::kCscEntries / 4) + i];

    HKEY hk;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SYSTEM\\GWE", 0, 0, &hk) == ERROR_SUCCESS) {
        RegSetValueExW(hk, L"SysColor", 0, REG_BINARY, (LPBYTE)colors, count * 4);
        RegCloseKey(hk);
    }
    HKEY hkApp;
    if (RegOpenKeyExW(HKEY_CURRENT_USER, L"ControlPanel\\Appearance", 0, 0, &hkApp) == ERROR_SUCCESS) {
        RegSetValueExW(hkApp, L"Current", 0, REG_SZ, (LPBYTE)L"CERF Theme", sizeof(L"CERF Theme"));
        RegCloseKey(hkApp);
    }
    CERF_LOG_X("cerf_guest: color scheme applied entries", count);
    return TRUE;
}

static void CerfSetFontHeight(const WCHAR* path, LONG height) {
    HKEY  hk;
    DWORD ht_in_pts = 0;

    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, path, 0, 0, &hk) != ERROR_SUCCESS)
        return;
    RegSetValueExW(hk, L"Ht", 0, REG_DWORD, (LPBYTE)&height, sizeof(height));
    RegSetValueExW(hk, L"HtInPts", 0, REG_DWORD, (LPBYTE)&ht_in_pts,
                   sizeof(ht_in_pts));
    RegCloseKey(hk);
    CERF_LOG_X("cerf_guest: system font Ht set", (DWORD)height);
}

static BOOL CerfApplySystemFont(void) {
    int i;
    if (!g_FbSystemFontPresent) return FALSE;
    for (i = 0; i < (int)(sizeof(kCerfFontKeys) / sizeof(kCerfFontKeys[0])); ++i)
        CerfSetFontHeight(kCerfFontKeys[i], g_FbSystemFontHeight);
    return TRUE;
}

static void CerfFlushRegistry(void) {
    HMODULE core = LoadLibraryW(L"coredll.dll");
    PFN_RegFlushKey flush = core
        ? (PFN_RegFlushKey)GetProcAddressW(core, L"RegFlushKey") : NULL;
    if (!flush) {
        CERF_LOG("cerf_guest: no RegFlushKey - registry is the object store");
        return;
    }
    CERF_LOG_X("cerf_guest: registry customizations flush rc",
               (DWORD)flush(HKEY_LOCAL_MACHINE));
}

static void CerfSignalCustomizationsApplied(void) {
    volatile ULONG* fb = (volatile ULONG*)CerfMapRegsPage(
        g_CerfVirtBase + CerfVirt::kFramebufferRegsOffset,
        CerfVirt::kFramebufferRegsSize);
    if (!fb) return;
    fb[CerfVirt::kFbRegCustomizationsApplied / 4] = 1u;
}

extern "C" void CerfApplyRegistryCustomizations(void) {
    BOOL wrote = FALSE;
    if (CerfApplyColorScheme()) wrote = TRUE;
    if (CerfApplySystemFont())  wrote = TRUE;
    if (!wrote) return;
    CerfFlushRegistry();
    CerfSignalCustomizationsApplied();
}
