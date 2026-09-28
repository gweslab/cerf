#pragma once

#include <windows.h>
#include "include/ddraw_ce6.h"

extern "C" DWORD WINAPI CerfGetBltStatus(Ce6_DDHAL_GETBLTSTATUSDATA* pd);
extern "C" DWORD WINAPI CerfDDGPELockWrap(Ce6_DDHAL_LOCKDATA* pd);
extern "C" DWORD WINAPI CerfDDGPEUnlockWrap(Ce6_DDHAL_UNLOCKDATA* pd);
extern "C" DWORD WINAPI CerfHalGetDriverInfo(Ce6_DDHAL_GETDRIVERINFODATA* lpInput);
