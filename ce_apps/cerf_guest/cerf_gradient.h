#pragma once

#include <windows.h>
#include <winddi.h>

extern "C" BOOL APIENTRY CerfDrvGradientFill(SURFOBJ*, CLIPOBJ*, XLATEOBJ*, TRIVERTEX*, ULONG,
                                             PVOID, ULONG, RECTL*, POINTL*, ULONG);
extern "C" BOOL APIENTRY CerfDrvAlphaBlend(SURFOBJ*, SURFOBJ*, CLIPOBJ*, XLATEOBJ*, RECTL*,
                                           RECTL*, BLENDOBJ*);
