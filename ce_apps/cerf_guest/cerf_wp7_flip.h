#pragma once

#include <windows.h>
#include <winddi.h>

extern "C" VOID  CerfWp7FullScreenSurface(SURFOBJ* pso);
extern "C" int   InitializeFlipping(DWORD display);
extern "C" int   TerminateFlipping(DWORD display);
extern "C" int   ScreenUpdateByFlipEx(DWORD display, const DWORD* record);
extern "C" DWORD ClaimFreeBuffer(DWORD display);
extern "C" int   SetSurfaceModified(void* surface);
