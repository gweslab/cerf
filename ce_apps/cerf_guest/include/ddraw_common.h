#pragma once

#include <windows.h>

#pragma pack(push, 4)

typedef struct _CerfDDCOLORKEY {
    DWORD dwColorSpaceLowValue;
    DWORD dwColorSpaceHighValue;
} CerfDDCOLORKEY;

typedef struct _CerfDDSCAPS {
    DWORD dwCaps;
} CerfDDSCAPS;

typedef struct _CerfDDPIXELFORMAT {
    DWORD dwSize;
    DWORD dwFlags;
    DWORD dwFourCC;
    union { DWORD dwRGBBitCount; DWORD dwYUVBitCount; DWORD dwAlphaBitDepth; };
    union { DWORD dwRBitMask; DWORD dwYBitMask; };
    union { DWORD dwGBitMask; DWORD dwUBitMask; };
    union { DWORD dwBBitMask; DWORD dwVBitMask; };
    union { DWORD dwRGBAlphaBitMask; DWORD dwYUVAlphaBitMask; };
} CerfDDPIXELFORMAT;

typedef struct _CerfDDBLTFX {
    DWORD          dwSize;
    DWORD          dwROP;
    DWORD          dwFillColor;
    CerfDDCOLORKEY ddckDestColorkey;
    CerfDDCOLORKEY ddckSrcColorkey;
} CerfDDBLTFX;

#pragma pack(pop)

typedef struct _CerfDDrawGbl* CerfDDrawGbl;

#define DDHAL_DRIVER_NOTHANDLED 0x00000000
#define DDHAL_DRIVER_HANDLED    0x00000001

#define CERF_FACDD 0x876
#define CERF_MAKE_DDHRESULT(code) MAKE_HRESULT(1, CERF_FACDD, code)

#define CERF_DD_OK                    S_OK
#define CERF_DDERR_GENERIC            E_FAIL
#define CERF_DDERR_INVALIDPARAMS      E_INVALIDARG
#define CERF_DDERR_OUTOFMEMORY        E_OUTOFMEMORY
#define CERF_DDERR_CURRENTLYNOTAVAIL  CERF_MAKE_DDHRESULT(40)
#define CERF_DDERR_INVALIDOBJECT      CERF_MAKE_DDHRESULT(130)
#define CERF_DDERR_NOCOLORKEYHW       CERF_MAKE_DDHRESULT(215)
#define CERF_DDERR_OUTOFVIDEOMEMORY   CERF_MAKE_DDHRESULT(380)
#define CERF_DDERR_UNSUPPORTEDFORMAT  CERF_MAKE_DDHRESULT(536)
#define CERF_DDERR_WASSTILLDRAWING    CERF_MAKE_DDHRESULT(540)
#define CERF_DDERR_UNSUPPORTEDMODE    CERF_MAKE_DDHRESULT(590)

#define CERF_DDPF_ALPHAPIXELS     0x00000001
#define CERF_DDPF_ALPHA           0x00000002
#define CERF_DDPF_FOURCC          0x00000004
#define CERF_DDPF_PALETTEINDEXED  0x00000020
#define CERF_DDPF_RGB             0x00000040

#define CERF_DDCKEY_SRCBLT        0x00000008
#define CERF_DDGFS_CANFLIP        0x00000001
#define CERF_DDFLIP_WAITVSYNC     0x00000001
#define CERF_DDLOCK_WAITNOTBUSY   0x00000008
#define CERF_DDWAITVB_BLOCKBEGIN  0x00000001
#define CERF_DDWAITVB_BLOCKEND    0x00000004

#define CERF_DD_ROP_SPACE (256 / 32)
#define CERF_SETROPBIT(array, rop) array[((rop) >> 21) & 0x07] |= (1 << (((rop) >> 16) & 0x1f))

#define CERF_DDBLTCAPS_READSYSMEM      0x00000001
#define CERF_DDBLTCAPS_WRITESYSMEM     0x00000002
#define CERF_DDCKEYCAPS_SRCBLT         0x00000200
#define CERF_DDALPHACAPS_ALPHAPIXELS   0x00000001
#define CERF_DDALPHACAPS_ALPHACONSTANT 0x00000008
#define CERF_DDALPHACAPS_NONPREMULT    0x00000080
