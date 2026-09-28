#pragma once

#include <winddi.h>

extern "C" PFN_BRUSHOBJ_pvAllocRbrush  BRUSHOBJ_pvAllocRbrush;
extern "C" PFN_BRUSHOBJ_pvGetRbrush    BRUSHOBJ_pvGetRbrush;
extern "C" PFN_CLIPOBJ_cEnumStart      CLIPOBJ_cEnumStart;
extern "C" PFN_CLIPOBJ_bEnum           CLIPOBJ_bEnum;
extern "C" PFN_PALOBJ_cGetColors       PALOBJ_cGetColors;
extern "C" PFN_PATHOBJ_vEnumStart      PATHOBJ_vEnumStart;
extern "C" PFN_PATHOBJ_bEnum           PATHOBJ_bEnum;
extern "C" PFN_XLATEOBJ_cGetPalette    XLATEOBJ_cGetPalette;
extern "C" PFN_EngCreateDeviceSurface  EngCreateDeviceSurface;
extern "C" PFN_EngDeleteSurface        EngDeleteSurface;
extern "C" PFN_EngCreateDeviceBitmap   EngCreateDeviceBitmap;
extern "C" PFN_EngCreatePalette        EngCreatePalette;
