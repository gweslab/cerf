#pragma once

#include <windows.h>

extern "C" void CerfAdvertiseDisplayPower(void);
extern "C" BOOL CerfIsPowerIoctl(ULONG iEsc);
extern "C" BOOL CerfPowerEscape(ULONG iEsc, ULONG cjOut, void* pvOut, ULONG* pRet);
