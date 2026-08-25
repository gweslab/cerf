#pragma once

#include <windows.h>

#ifdef __cplusplus
extern "C" {
#endif

const WCHAR* CerfBasenameW(const WCHAR* p);

BOOL CerfWindowOwnerIs(HWND w, const WCHAR* exe);

#ifdef __cplusplus
}
#endif
