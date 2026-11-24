#pragma once

#include <windows.h>
#include <winddi.h>

BOOL CerfWp7Escape(SURFOBJ* pso, ULONG iEsc, ULONG cjIn, PVOID pvIn, ULONG cjOut, PVOID pvOut,
                   ULONG* pRet);
ULONG CerfWp7TextGammaAa(void);
ULONG CerfWp7TextGammaClearType(void);
