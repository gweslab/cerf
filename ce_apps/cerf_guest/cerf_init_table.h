#pragma once

#include <windows.h>

#define CERF_INIT_EXE_WCHARS 64

typedef struct { int ord; WCHAR exe[CERF_INIT_EXE_WCHARS]; } CerfLaunchEntry;

#ifdef __cplusplus
extern "C" {
#endif

int CerfReadInitTable(CerfLaunchEntry* tbl, int max);

#ifdef __cplusplus
}
#endif
