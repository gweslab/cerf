#include <winddi.h>
#include "cerf_eng_callbacks.h"

PFN_BRUSHOBJ_pvAllocRbrush  BRUSHOBJ_pvAllocRbrush  = NULL;
PFN_BRUSHOBJ_pvGetRbrush    BRUSHOBJ_pvGetRbrush    = NULL;
PFN_CLIPOBJ_cEnumStart      CLIPOBJ_cEnumStart      = NULL;
PFN_CLIPOBJ_bEnum           CLIPOBJ_bEnum           = NULL;
PFN_PALOBJ_cGetColors       PALOBJ_cGetColors       = NULL;
PFN_PATHOBJ_vEnumStart      PATHOBJ_vEnumStart      = NULL;
PFN_PATHOBJ_bEnum           PATHOBJ_bEnum           = NULL;
PFN_XLATEOBJ_cGetPalette    XLATEOBJ_cGetPalette    = NULL;
PFN_EngCreateDeviceSurface  EngCreateDeviceSurface  = NULL;
PFN_EngDeleteSurface        EngDeleteSurface        = NULL;
PFN_EngCreateDeviceBitmap   EngCreateDeviceBitmap   = NULL;
PFN_EngCreatePalette        EngCreatePalette        = NULL;
