
#pragma once

#include <windows.h>

#pragma pack(push, 4)

typedef struct _Ce5_DDPIXELFORMAT {
    DWORD dwSize;
    DWORD dwFlags;
    DWORD dwFourCC;
    union { DWORD dwRGBBitCount; DWORD dwYUVBitCount; DWORD dwAlphaBitDepth; };
    union { DWORD dwRBitMask; DWORD dwYBitMask; };
    union { DWORD dwGBitMask; DWORD dwUBitMask; };
    union { DWORD dwBBitMask; DWORD dwVBitMask; };
    union { DWORD dwRGBAlphaBitMask; DWORD dwYUVAlphaBitMask; };
} Ce5_DDPIXELFORMAT;

typedef struct _Ce5_DDSCAPS { DWORD dwCaps; } Ce5_DDSCAPS;

typedef struct _Ce5_VIDMEMINFO {
    DWORD               fpPrimary;
    DWORD               dwFlags;
    DWORD               dwDisplayWidth;
    DWORD               dwDisplayHeight;
    LONG                lDisplayPitch;
    Ce5_DDPIXELFORMAT   ddpfDisplay;
    DWORD               dwOffscreenAlign;
    DWORD               dwOverlayAlign;
    DWORD               dwTextureAlign;
    DWORD               dwZBufferAlign;
    DWORD               dwAlphaAlign;
    DWORD               dwNumHeaps;
    DWORD               pvmList;
} Ce5_VIDMEMINFO;

#define CE5_DD_ROP_SPACE (256 / 32)

typedef struct _Ce5_DDCORECAPS {
    DWORD       dwSize;
    DWORD       dwCaps;
    DWORD       dwCaps2;
    DWORD       dwCKeyCaps;
    DWORD       dwFXCaps;
    DWORD       dwFXAlphaCaps;
    DWORD       dwPalCaps;
    DWORD       dwSVCaps;
    DWORD       dwAlphaBltConstBitDepths;
    DWORD       dwAlphaBltPixelBitDepths;
    DWORD       dwAlphaBltSurfaceBitDepths;
    DWORD       dwAlphaOverlayConstBitDepths;
    DWORD       dwAlphaOverlayPixelBitDepths;
    DWORD       dwAlphaOverlaySurfaceBitDepths;
    DWORD       dwZBufferBitDepths;
    DWORD       dwVidMemTotal;
    DWORD       dwVidMemFree;
    DWORD       dwMaxVisibleOverlays;
    DWORD       dwCurrVisibleOverlays;
    DWORD       dwNumFourCCCodes;
    DWORD       dwAlignBoundarySrc;
    DWORD       dwAlignSizeSrc;
    DWORD       dwAlignBoundaryDest;
    DWORD       dwAlignSizeDest;
    DWORD       dwAlignStrideAlign;
    DWORD       dwRops[CE5_DD_ROP_SPACE];
    Ce5_DDSCAPS ddsCaps;
    DWORD       dwMinOverlayStretch;
    DWORD       dwMaxOverlayStretch;
    DWORD       dwMinLiveVideoStretch;
    DWORD       dwMaxLiveVideoStretch;
    DWORD       dwMinHwCodecStretch;
    DWORD       dwMaxHwCodecStretch;
    DWORD       dwReserved1;
    DWORD       dwReserved2;
    DWORD       dwReserved3;
    DWORD       dwSVBCaps;
    DWORD       dwSVBCKeyCaps;
    DWORD       dwSVBFXCaps;
    DWORD       dwSVBRops[CE5_DD_ROP_SPACE];
    DWORD       dwVSBCaps;
    DWORD       dwVSBCKeyCaps;
    DWORD       dwVSBFXCaps;
    DWORD       dwVSBRops[CE5_DD_ROP_SPACE];
    DWORD       dwSSBCaps;
    DWORD       dwSSBCKeyCaps;
    DWORD       dwSSBFXCaps;
    DWORD       dwSSBRops[CE5_DD_ROP_SPACE];
    DWORD       dwMaxVideoPorts;
    DWORD       dwCurrVideoPorts;
    DWORD       dwSVBCaps2;
} Ce5_DDCORECAPS;

typedef struct _Ce5_DDHAL_DDCALLBACKS {
    DWORD dwSize;
    DWORD dwFlags;
    PVOID DestroyDriver;
    PVOID CreateSurface;
    PVOID SetColorKey;
    PVOID SetMode;
    PVOID WaitForVerticalBlank;
    PVOID CanCreateSurface;
    PVOID CreatePalette;
    PVOID GetScanLine;
    PVOID SetExclusiveMode;
    PVOID FlipToGDISurface;
} Ce5_DDHAL_DDCALLBACKS;

typedef struct _Ce5_DDHAL_DDSURFACECALLBACKS {
    DWORD dwSize;
    DWORD dwFlags;
    PVOID DestroySurface;
    PVOID Flip;
    PVOID SetClipList;
    PVOID Lock;
    PVOID Unlock;
    PVOID Blt;
    PVOID SetColorKey;
    PVOID AddAttachedSurface;
    PVOID GetBltStatus;
    PVOID GetFlipStatus;
    PVOID UpdateOverlay;
    PVOID SetOverlayPosition;
    PVOID reserved4;
    PVOID SetPalette;
    PVOID reserved5;
    PVOID reserved6;
} Ce5_DDHAL_DDSURFACECALLBACKS;

typedef struct _Ce5_DDHALMODEINFO {
    DWORD dwWidth;
    DWORD dwHeight;
    LONG  lPitch;
    DWORD dwBPP;
    WORD  wFlags;
    WORD  wRefreshRate;
    DWORD dwRBitMask;
    DWORD dwGBitMask;
    DWORD dwBBitMask;
    DWORD dwAlphaBitMask;
} Ce5_DDHALMODEINFO;

typedef struct _Ce5_DDHALINFO {
    DWORD           dwSize;
    PVOID           lpDDCallbacks;
    PVOID           lpDDSurfaceCallbacks;
    PVOID           lpDDPaletteCallbacks;
    Ce5_VIDMEMINFO  vmiData;
    Ce5_DDCORECAPS  ddCaps;
    DWORD           dwMonitorFrequency;
    PVOID           GetDriverInfo;
    DWORD           dwModeIndex;
    PVOID           lpdwFourCC;
    DWORD           dwNumModes;
    PVOID           lpModeInfo;
    DWORD           dwFlags;
    PVOID           lpPDevice;
    DWORD           hInstance;
    ULONG_PTR       lpD3DGlobalDriverData;
    ULONG_PTR       lpD3DHALCallbacks;
    PVOID           lpDDExeBufCallbacks;
} Ce5_DDHALINFO;

typedef struct _Ce5_DDHAL_CREATESURFACEDATA {
    PVOID   lpDD;
    PVOID   lpDDSurfaceDesc;
    PVOID*  lplpSList;
    DWORD   dwSCnt;
    HRESULT ddRVal;
    PVOID   CreateSurface;
} Ce5_DDHAL_CREATESURFACEDATA;

typedef struct _Ce5_DDHAL_LOCKDATA {
    PVOID   lpDD;
    PVOID   lpDDSurface;
    DWORD   bHasRect;
    RECTL   rArea;
    PVOID   lpSurfData;
    HRESULT ddRVal;
    PVOID   Lock;
    DWORD   dwFlags;
} Ce5_DDHAL_LOCKDATA;

#pragma pack(pop)

extern "C" BOOL Ce5HALInit(void* lpddhi);
