#include <windows.h>

#include "cerf_debug_log.h"

extern LONG  g_FbSystemFontHeight;
extern ULONG g_FbSystemFontPresent;

static const WCHAR* const kCerfFontKeys[] = {
    L"System\\GDI\\SYSFNT",
    L"System\\GWE\\Menu\\BarFnt",
    L"System\\GWE\\Menu\\PopFnt",
    L"System\\GWE\\OOMFnt",
};

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

extern "C" void CerfApplySystemFont(void) {
    int i;
    if (!g_FbSystemFontPresent) return;
    for (i = 0; i < (int)(sizeof(kCerfFontKeys) / sizeof(kCerfFontKeys[0])); ++i)
        CerfSetFontHeight(kCerfFontKeys[i], g_FbSystemFontHeight);
}
