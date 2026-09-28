
#pragma once

#include <windows.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef ULONG ROP4;
typedef ULONG MIX;
typedef ULONG FLONG;

DECLARE_HANDLE(HBM);
DECLARE_HANDLE(HDEV);
DECLARE_HANDLE(HSURF);
DECLARE_HANDLE(DHSURF);
DECLARE_HANDLE(DHPDEV);

typedef union _FLOAT_LONG {
    FLOAT e;
    LONG  l;
} FLOAT_LONG, *PFLOAT_LONG;

typedef LONG FIX;
typedef FIX* PFIX;

typedef struct _POINTFIX {
    FIX x;
    FIX y;
} POINTFIX, *PPOINTFIX;

typedef struct _RECTFX {
    FIX xLeft;
    FIX yTop;
    FIX xRight;
    FIX yBottom;
} RECTFX, *PRECTFX;

#define LTOFX(x)        ((x) << 4)
#define FXTOL(x)        ((x) >> 4)
#define FXTOLFLOOR(x)   ((x) >> 4)
#define FXTOLCEILING(x) (((x) + 0x0F) >> 4)
#define FXTOLROUND(x)   ((((x) >> 3) + 1) >> 1)

#ifndef GRADIENT_FILL_RECT_H
typedef USHORT COLOR16;
typedef struct _TRIVERTEX {
    LONG    x;
    LONG    y;
    COLOR16 Red;
    COLOR16 Green;
    COLOR16 Blue;
    COLOR16 Alpha;
} TRIVERTEX, *PTRIVERTEX, *LPTRIVERTEX;

typedef struct _GRADIENT_TRIANGLE {
    ULONG Vertex1;
    ULONG Vertex2;
    ULONG Vertex3;
} GRADIENT_TRIANGLE, *PGRADIENT_TRIANGLE, *LPGRADIENT_TRIANGLE;

typedef struct _GRADIENT_RECT {
    ULONG UpperLeft;
    ULONG LowerRight;
} GRADIENT_RECT, *PGRADIENT_RECT, *LPGRADIENT_RECT;

#define GRADIENT_FILL_RECT_H   0x00000000
#define GRADIENT_FILL_RECT_V   0x00000001
#define GRADIENT_FILL_TRIANGLE 0x00000002
#define GRADIENT_FILL_OP_FLAG  0x000000ff
#endif

#ifndef _BLENDFUNCTION_DEFINED
#define _BLENDFUNCTION_DEFINED
typedef struct _BLENDFUNCTION {
    BYTE BlendOp;
    BYTE BlendFlags;
    BYTE SourceConstantAlpha;
    BYTE AlphaFormat;
} BLENDFUNCTION, *PBLENDFUNCTION;
#endif

#ifndef AC_SRC_OVER
#define AC_SRC_OVER  0x00
#define AC_SRC_ALPHA 0x01
#endif

#define PD_BEGINSUBPATH 0x00000001
#define PD_ENDSUBPATH   0x00000002
#define PD_RESETSTYLE   0x00000004
#define PD_CLOSEFIGURE  0x00000008
#define PD_BEZIERS      0x00000010

typedef struct _PATHDATA {
    FLONG     flags;
    ULONG     count;
    POINTFIX* pptfx;
} PATHDATA, *PPATHDATA;

#define BMF_1BPP  1L
#define BMF_2BPP  9L
#define BMF_4BPP  2L
#define BMF_8BPP  3L
#define BMF_16BPP 4L
#define BMF_24BPP 5L
#define BMF_32BPP 6L

#define BMF_USERMEM      0x0008
#define BMF_SRCPREROTATE 0x8000

#define STYPE_BITMAP 0L
#define STYPE_DEVICE 1L

#define PAL_INDEXED   0x00000001
#define PAL_BITFIELDS 0x00000002
#define PAL_RGB       0x00000004
#define PAL_BGR       0x00000008
#define PAL_FOURCC    0x00000010

#define XO_TRIVIAL 0x00000001
#define XO_TABLE   0x00000002
#define XO_TO_MONO 0x00000004

#define XO_SRCPALETTE    1
#define XO_DESTPALETTE   2
#define XO_DESTDCPALETTE 3

#define DC_TRIVIAL 0
#define DC_RECT    1
#define DC_COMPLEX 3

#define CT_RECTANGLES 0L
#define CD_RIGHTDOWN  0L
#define CD_LEFTDOWN   1L
#define CD_ANY        4L

#define BLT_DSTTRANSPARENT 2
#define BLT_TRANSPARENT    4
#define BLT_STRETCH        8
#define BLT_ALPHABLEND     16
#define BLT_ALPHASRCNEG    32
#define BLT_ALPHADESTNEG   64
#define BLT_WAITNOTBUSY    1024
#define BLT_WAITVSYNC      2048

#define SPS_ERROR            0
#define SPS_DECLINE          1
#define SPS_ACCEPT_NOEXCLUDE 2
#define SPS_ACCEPT_EXCLUDE   3

#define GCAPS_GRAY16                        0x01000000
#define GCAPS_CLEARTYPE                     0x00000100
#define GCAPS_CLEARTYPE_HORIZONTALY_STRIPED 0x00000200
#define GCAPS_TEXT_CAPS (GCAPS_GRAY16 | GCAPS_CLEARTYPE | GCAPS_CLEARTYPE_HORIZONTALY_STRIPED)

#define DDI_DRIVER_VERSION 0x00040001

typedef struct _SURFOBJ {
    DHSURF dhsurf;
    HSURF  hsurf;
    DHPDEV dhpdev;
    HDEV   hdev;
    SIZEL  sizlBitmap;
    ULONG  cjBits;
    PVOID  pvBits;
    PVOID  pvScan0;
    LONG   lDelta;
    ULONG  iUniq;
    ULONG  iBitmapFormat;
    USHORT iType;
    USHORT fjBitmap;
} SURFOBJ;

typedef struct _CLIPOBJ {
    ULONG iUniq;
    RECTL rclBounds;
    BYTE  iDComplexity;
    BYTE  iFComplexity;
    BYTE  iMode;
    BYTE  fjOptions;
} CLIPOBJ;

typedef struct _BRUSHOBJ {
    ULONG iSolidColor;
    PVOID pvRbrush;
} BRUSHOBJ;

typedef struct _XLATEOBJ {
    ULONG  iUniq;
    FLONG  flXlate;
    USHORT iSrcType;
    USHORT iDstType;
    ULONG  cEntries;
    ULONG* pulXlate;
} XLATEOBJ;

typedef struct _PATHOBJ {
    FLONG fl;
    ULONG cCurves;
} PATHOBJ;

typedef struct _XFORMOBJ {
    ULONG ulReserved;
} XFORMOBJ;

typedef struct _PALOBJ {
    ULONG ulReserved;
} PALOBJ;

typedef struct _ENUMRECTS {
    ULONG c;
    RECTL arcl[1];
} ENUMRECTS;

#define LA_GEOMETRIC 0x00000001
#define LA_ALTERNATE 0x00000002
#define LA_STARTGAP  0x00000004
#define LA_STYLED    0x00000008

typedef struct _LINEATTRS {
    FLONG       fl;
    ULONG       iJoin;
    ULONG       iEndCap;
    FLOAT_LONG  elWidth;
    FLOAT       eMiterLimit;
    ULONG       cstyle;
    PFLOAT_LONG pstyle;
    FLOAT_LONG  elStyleState;
} LINEATTRS, *PLINEATTRS;

typedef struct tagBLENDOBJ {
    BLENDFUNCTION BlendFunction;
} BLENDOBJ, *PBLENDOBJ;

typedef struct tagDEVINFO {
    FLONG    flGraphicsCaps;
    LOGFONTW lfDefaultFont;
    LOGFONTW lfAnsiVarFont;
    LOGFONTW lfAnsiFixFont;
    ULONG    cFonts;
    ULONG    iDitherFormat;
    USHORT   cxDither;
    USHORT   cyDither;
    HPALETTE hpalDefault;
} DEVINFO, *PDEVINFO;

typedef struct _GDIINFO {
    ULONG  ulVersion;
    ULONG  ulTechnology;
    ULONG  ulHorzSize;
    ULONG  ulVertSize;
    ULONG  ulHorzRes;
    ULONG  ulVertRes;
    ULONG  cBitsPixel;
    ULONG  cPlanes;
    ULONG  ulNumColors;
    ULONG  flRaster;
    ULONG  ulLogPixelsX;
    ULONG  ulLogPixelsY;
    ULONG  flTextCaps;
    ULONG  flShadeBlendCaps;
    ULONG  ulDACRed;
    ULONG  ulDACGreen;
    ULONG  ulDACBlue;
    ULONG  ulAspectX;
    ULONG  ulAspectY;
    ULONG  ulAspectXY;
    LONG   xStyleStep;
    LONG   yStyleStep;
    LONG   denStyleStep;
    POINTL ptlPhysOffset;
    SIZEL  szlPhysSize;
    ULONG  ulNumPalReg;
    ULONG  ulDevicePelsDPI;
    ULONG  ulPrimaryOrder;
    ULONG  ulHTPatternSize;
    ULONG  ulHTOutputFormat;
    ULONG  flHTFlags;
    ULONG  ulVRefresh;
    ULONG  ulBltAlignment;
    ULONG  ulPanningHorzRes;
    ULONG  ulPanningVertRes;
    LONG   lStride;
} GDIINFO, *PGDIINFO;

typedef DHPDEV  (*PFN_DrvEnablePDEV)(DEVMODEW*, LPWSTR, ULONG, HSURF*, ULONG, ULONG*, ULONG, DEVINFO*, HDEV, LPWSTR, HANDLE);
typedef VOID    (*PFN_DrvDisablePDEV)(DHPDEV);
typedef HSURF   (*PFN_DrvEnableSurface)(DHPDEV);
typedef VOID    (*PFN_DrvDisableSurface)(DHPDEV);
typedef HBITMAP (*PFN_DrvCreateDeviceBitmap)(DHPDEV, SIZEL, ULONG);
typedef VOID    (*PFN_DrvDeleteDeviceBitmap)(DHSURF);
typedef BOOL    (*PFN_DrvRealizeBrush)(BRUSHOBJ*, SURFOBJ*, SURFOBJ*, SURFOBJ*, XLATEOBJ*, ULONG);
typedef BOOL    (*PFN_DrvStrokePath)(SURFOBJ*, PATHOBJ*, CLIPOBJ*, XFORMOBJ*, BRUSHOBJ*, POINTL*, LINEATTRS*, MIX);
typedef BOOL    (*PFN_DrvFillPath)(SURFOBJ*, PATHOBJ*, CLIPOBJ*, BRUSHOBJ*, POINTL*, MIX, FLONG);
typedef BOOL    (*PFN_DrvPaint)(SURFOBJ*, CLIPOBJ*, BRUSHOBJ*, POINTL*, MIX);
typedef BOOL    (*PFN_DrvBitBlt)(SURFOBJ*, SURFOBJ*, SURFOBJ*, CLIPOBJ*, XLATEOBJ*, RECTL*, POINTL*, POINTL*, BRUSHOBJ*, POINTL*, ROP4);
typedef BOOL    (*PFN_DrvCopyBits)(SURFOBJ*, SURFOBJ*, CLIPOBJ*, XLATEOBJ*, RECTL*, POINTL*);
typedef BOOL    (*PFN_DrvAnyBlt)(SURFOBJ*, SURFOBJ*, SURFOBJ*, CLIPOBJ*, XLATEOBJ*, POINTL*, RECTL*, RECTL*, POINTL*, BRUSHOBJ*, POINTL*, ROP4, ULONG, ULONG);
typedef BOOL    (*PFN_DrvTransparentBlt)(SURFOBJ*, SURFOBJ*, CLIPOBJ*, XLATEOBJ*, RECTL*, RECTL*, ULONG);
typedef BOOL    (*PFN_DrvSetPalette)(DHPDEV, PALOBJ*, FLONG, ULONG, ULONG);
typedef ULONG   (*PFN_DrvSetPointerShape)(SURFOBJ*, SURFOBJ*, SURFOBJ*, XLATEOBJ*, LONG, LONG, LONG, LONG, RECTL*, FLONG);
typedef VOID    (*PFN_DrvMovePointer)(SURFOBJ*, LONG, LONG, RECTL*);
typedef ULONG   (*PFN_DrvGetModes)(HANDLE, ULONG, DEVMODEW*);
typedef ULONG   (*PFN_DrvRealizeColor)(USHORT, ULONG, ULONG*, ULONG);
typedef ULONG*  (*PFN_DrvGetMasks)(DHPDEV);
typedef ULONG   (*PFN_DrvUnrealizeColor)(USHORT, ULONG, ULONG*, ULONG);
typedef BOOL    (*PFN_DrvContrastControl)(DHPDEV, ULONG, ULONG*);
typedef VOID    (*PFN_DrvPowerHandler)(DHPDEV, BOOL);
typedef BOOL    (*PFN_DrvEndDoc)(SURFOBJ*, FLONG);
typedef BOOL    (*PFN_DrvStartDoc)(SURFOBJ*, PWSTR, DWORD);
typedef BOOL    (*PFN_DrvStartPage)(SURFOBJ*);
typedef ULONG   (*PFN_DrvEscape)(DHPDEV, SURFOBJ*, ULONG, ULONG, PVOID, ULONG, PVOID);
typedef BOOL    (*PFN_DrvGradientFill)(SURFOBJ*, CLIPOBJ*, XLATEOBJ*, TRIVERTEX*, ULONG, PVOID, ULONG, RECTL*, POINTL*, ULONG);
typedef BOOL    (*PFN_DrvAlphaBlend)(SURFOBJ*, SURFOBJ*, CLIPOBJ*, XLATEOBJ*, RECTL*, RECTL*, BLENDOBJ*);
typedef BOOL    (*PFN_DrvExclusiveMode)(DHPDEV, BOOL);
typedef VOID    (*PFN_DrvDisableDriver)(void);

typedef struct tagDrvEnableData {
    PFN_DrvEnablePDEV         DrvEnablePDEV;
    PFN_DrvDisablePDEV        DrvDisablePDEV;
    PFN_DrvEnableSurface      DrvEnableSurface;
    PFN_DrvDisableSurface     DrvDisableSurface;
    PFN_DrvCreateDeviceBitmap DrvCreateDeviceBitmap;
    PFN_DrvDeleteDeviceBitmap DrvDeleteDeviceBitmap;
    PFN_DrvRealizeBrush       DrvRealizeBrush;
    PFN_DrvStrokePath         DrvStrokePath;
    PFN_DrvFillPath           DrvFillPath;
    PFN_DrvPaint              DrvPaint;
    PFN_DrvBitBlt             DrvBitBlt;
    PFN_DrvCopyBits           DrvCopyBits;
    PFN_DrvAnyBlt             DrvAnyBlt;
    PFN_DrvTransparentBlt     DrvTransparentBlt;
    PFN_DrvSetPalette         DrvSetPalette;
    PFN_DrvSetPointerShape    DrvSetPointerShape;
    PFN_DrvMovePointer        DrvMovePointer;
    PFN_DrvGetModes           DrvGetModes;
    PFN_DrvRealizeColor       DrvRealizeColor;
    PFN_DrvGetMasks           DrvGetMasks;
    PFN_DrvUnrealizeColor     DrvUnrealizeColor;
    PFN_DrvContrastControl    DrvContrastControl;
    PFN_DrvPowerHandler       DrvPowerHandler;
    PFN_DrvEndDoc             DrvEndDoc;
    PFN_DrvStartDoc           DrvStartDoc;
    PFN_DrvStartPage          DrvStartPage;
    PFN_DrvEscape             DrvEscape;
    PFN_DrvGradientFill       DrvGradientFill;
    PFN_DrvAlphaBlend         DrvAlphaBlend;
    PFN_DrvExclusiveMode      DrvExclusiveMode;
    PFN_DrvDisableDriver      DrvDisableDriver;
} DRVENABLEDATA, *PDRVENABLEDATA;

typedef PVOID    (*PFN_BRUSHOBJ_pvAllocRbrush)(BRUSHOBJ*, ULONG);
typedef PVOID    (*PFN_BRUSHOBJ_pvGetRbrush)(BRUSHOBJ*);
typedef ULONG    (*PFN_CLIPOBJ_cEnumStart)(CLIPOBJ*, BOOL, ULONG, ULONG, ULONG);
typedef BOOL     (*PFN_CLIPOBJ_bEnum)(CLIPOBJ*, ULONG, ULONG*);
typedef ULONG    (*PFN_PALOBJ_cGetColors)(PALOBJ*, ULONG, ULONG, ULONG*);
typedef VOID     (*PFN_PATHOBJ_vEnumStart)(PATHOBJ*);
typedef BOOL     (*PFN_PATHOBJ_bEnum)(PATHOBJ*, PATHDATA*);
typedef VOID     (*PFN_PATHOBJ_vGetBounds)(PATHOBJ*, PRECTFX);
typedef ULONG    (*PFN_XLATEOBJ_cGetPalette)(XLATEOBJ*, ULONG, ULONG, ULONG*);
typedef HSURF    (*PFN_EngCreateDeviceSurface)(DHSURF, SIZEL, ULONG);
typedef BOOL     (*PFN_EngDeleteSurface)(HSURF);
typedef HBITMAP  (*PFN_EngCreateDeviceBitmap)(DHSURF, SIZEL, ULONG);
typedef HPALETTE (*PFN_EngCreatePalette)(ULONG, ULONG, PULONG, FLONG, FLONG, FLONG);
typedef BOOL     (*PFN_EngGetPaletteFromPool)(ULONG, ULONG**, int*);
typedef VOID     (*PFN_EngAddPaletteToPool)(ULONG, ULONG*, int);
typedef VOID     (*PFN_EngReleasePooledPalette)(ULONG, ULONG*, int);

typedef struct _ENGCALLBACKS {
    PFN_BRUSHOBJ_pvAllocRbrush  BRUSHOBJ_pvAllocRbrush;
    PFN_BRUSHOBJ_pvGetRbrush    BRUSHOBJ_pvGetRbrush;
    PFN_CLIPOBJ_cEnumStart      CLIPOBJ_cEnumStart;
    PFN_CLIPOBJ_bEnum           CLIPOBJ_bEnum;
    PFN_PALOBJ_cGetColors       PALOBJ_cGetColors;
    PFN_PATHOBJ_vEnumStart      PATHOBJ_vEnumStart;
    PFN_PATHOBJ_bEnum           PATHOBJ_bEnum;
    PFN_PATHOBJ_vGetBounds      PATHOBJ_vGetBounds;
    PFN_XLATEOBJ_cGetPalette    XLATEOBJ_cGetPalette;
    PFN_EngCreateDeviceSurface  EngCreateDeviceSurface;
    PFN_EngDeleteSurface        EngDeleteSurface;
    PFN_EngCreateDeviceBitmap   EngCreateDeviceBitmap;
    PFN_EngCreatePalette        EngCreatePalette;
    PFN_EngGetPaletteFromPool   EngGetPaletteFromPool;
    PFN_EngAddPaletteToPool     EngAddPaletteToPool;
    PFN_EngReleasePooledPalette EngReleasePooledPalette;
} ENGCALLBACKS, *PENGCALLBACKS;

#ifdef __cplusplus
}
#endif
