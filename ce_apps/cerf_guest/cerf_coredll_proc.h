#ifndef CERF_COREDLL_PROC_H
#define CERF_COREDLL_PROC_H

#include <windows.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef LONG   (WINAPI *PFN_RegDeleteValueW)(HKEY, LPCWSTR);
typedef HANDLE (*PFN_CreateAPISet)(char*, USHORT, const PFNVOID*, const ULONGLONG*);

FARPROC CerfCoredllProc(const wchar_t* name);

#ifdef __cplusplus
}
#endif

#endif
