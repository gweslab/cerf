#include <windows.h>

#include "cerf_init_table.h"

static int CerfParseLaunchName(const WCHAR* name, int* ord) {
    const WCHAR* pfx = L"launch";
    const WCHAR* p   = name;
    int v = 0;
    for (; *pfx; ++pfx, ++p) {
        WCHAR c = *p;
        if (c >= L'A' && c <= L'Z') c = (WCHAR)(c + 32);
        if (c != *pfx) return 0;
    }
    if (!(*p >= L'0' && *p <= L'9')) return 0;
    for (; *p >= L'0' && *p <= L'9'; ++p) v = v * 10 + (int)(*p - L'0');
    if (*p != 0) return 0;
    *ord = v;
    return 1;
}

extern "C" int CerfReadInitTable(CerfLaunchEntry* tbl, int max) {
    HKEY  hk;
    DWORD idx = 0;
    int   n   = 0;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"init", 0, 0, &hk) != ERROR_SUCCESS)
        return -1;
    for (;;) {
        WCHAR name[CERF_INIT_EXE_WCHARS];
        WCHAR data[MAX_PATH];
        DWORD nlen = CERF_INIT_EXE_WCHARS;
        DWORD dlen = sizeof(data);
        DWORD type = 0;
        int   ord, i;
        if (RegEnumValueW(hk, idx, name, &nlen, NULL, &type, (LPBYTE)data, &dlen) != ERROR_SUCCESS)
            break;
        idx++;
        if (type != REG_SZ) continue;
        if (!CerfParseLaunchName(name, &ord)) continue;
        if (n >= max) break;
        tbl[n].ord = ord;
        for (i = 0; i < CERF_INIT_EXE_WCHARS - 1 && data[i]; ++i)
            tbl[n].exe[i] = data[i];
        tbl[n].exe[i] = 0;
        n++;
    }
    RegCloseKey(hk);
    return n;
}
