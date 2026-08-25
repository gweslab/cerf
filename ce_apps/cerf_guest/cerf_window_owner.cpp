#include <windows.h>

#include "cerf_window_owner.h"

extern "C" const WCHAR* CerfBasenameW(const WCHAR* p) {
    const WCHAR* b = p;
    for (; *p; ++p)
        if (*p == L'\\' || *p == L'/') b = p + 1;
    return b;
}

extern "C" BOOL CerfWindowOwnerIs(HWND w, const WCHAR* exe) {
    DWORD  pid = 0;
    HANDLE hp;
    WCHAR  path[MAX_PATH];
    DWORD  n;

    GetWindowThreadProcessId(w, &pid);
    if (!pid) return FALSE;
    hp = OpenProcess(0, FALSE, pid);
    if (!hp) return FALSE;
    path[0] = 0;
    n = GetModuleFileNameW((HMODULE)hp, path, MAX_PATH);
    CloseHandle(hp);
    if (!n) return FALSE;

    return lstrcmpiW(CerfBasenameW(path), exe) == 0;
}
