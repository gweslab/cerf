#pragma once

#include <windows.h>

#ifndef DMDO_0
#define DMDO_0   0
#define DMDO_90  1
#define DMDO_180 2
#define DMDO_270 4
#endif

#define CERF_DMDO_TURNS (DMDO_90 | DMDO_180 | DMDO_270)

#ifndef CDS_TEST
#define CDS_TEST 0x00000002u
#endif
#ifndef CDS_RESET
#define CDS_RESET 0x40000000u
#endif
#ifndef DM_DISPLAYORIENTATION
#define DM_DISPLAYORIENTATION 0x00800000u
#endif
#ifndef DM_DISPLAYQUERYORIENTATION
#define DM_DISPLAYQUERYORIENTATION 0x01000000u
#endif
#ifndef DISP_CHANGE_SUCCESSFUL
#define DISP_CHANGE_SUCCESSFUL 0
#endif
#ifndef DISP_CHANGE_FAILED
#define DISP_CHANGE_FAILED (-1)
#endif
#ifndef DISP_CHANGE_BADMODE
#define DISP_CHANGE_BADMODE (-2)
#endif

typedef LONG (WINAPI *CerfChangeDisplaySettingsExFn)(LPCWSTR, DEVMODEW*, HWND, DWORD, LPVOID);

LONG CerfDisplayOrientationCall(CerfChangeDisplaySettingsExFn cds, DWORD fields, DWORD dmdo,
                                DWORD flags, DWORD* out_dmdo);

ULONG CerfDisplayOrientationQuarter(ULONG dmdo);
ULONG CerfDisplayOrientationOfQuarter(ULONG quarter);
BOOL  CerfDisplayOrientationSideways(ULONG dmdo);
