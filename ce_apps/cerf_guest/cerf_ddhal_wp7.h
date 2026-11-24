#pragma once

#include <windows.h>

extern "C" BOOL Wp7HALInit(void* lpddhi);

DWORD CerfWp7RgbStride(DWORD width, DWORD bpp);
DWORD CerfWp7RgbSurfaceBytes(DWORD width, DWORD height, DWORD bpp);
