#pragma once

#include <windows.h>

#define CERF_TP_SAMPLES     96
#define CERF_TP_SAMPLE_MS   250u
#define CERF_TP_UNITY       1000u
#define CERF_TP_FULL_SCALE  2000u

#ifdef __cplusplus
extern "C" {
#endif

void CerfStartTickProfiler(HMODULE self);

HMODULE CerfTickProfilerModule(void);

int  CerfTickProfilerSnapshot(DWORD* out, int max);

#ifdef __cplusplus
}
#endif
