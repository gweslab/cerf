#pragma once

#include <windows.h>
#include <tlhelp32.h>

#ifdef __cplusplus
extern "C" {
#endif

BOOL   CerfToolhelpReady(void);
HANDLE CerfToolhelpSnapshotProcesses(void);
BOOL   CerfToolhelpProcessFirst(HANDLE snap, LPPROCESSENTRY32 pe);
BOOL   CerfToolhelpProcessNext(HANDLE snap, LPPROCESSENTRY32 pe);
void   CerfToolhelpCloseSnapshot(HANDLE snap);

#ifdef __cplusplus
}
#endif
