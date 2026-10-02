#include <windows.h>

#include "cerf_allow_unsigned_apps.h"

static void CerfSetTrustDword(const WCHAR* key_path, const WCHAR* name, DWORD value) {
    HKEY  key;
    LONG  rc = RegOpenKeyExW(HKEY_LOCAL_MACHINE, key_path, 0, 0, &key);
    if (rc != ERROR_SUCCESS) return;
    rc = RegSetValueExW(key, name, 0, REG_DWORD, (const BYTE*)&value, sizeof(value));
    RegCloseKey(key);
    CERF_LOG_X("cerf_guest: unsigned-app trust value set rc", (ULONG)rc);
}

extern "C" void CerfAllowUnsignedApps(void) {
    CerfSetTrustDword(L"Security\\CertMod", L"AllowUntrustedApps", 1);
    CerfSetTrustDword(L"Security\\Policies\\Policies", L"0000101a", 1);
}
