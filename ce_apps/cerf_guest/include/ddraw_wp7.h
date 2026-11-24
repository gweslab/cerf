#pragma once

#include <windows.h>
#include "ddraw_common.h"

#pragma pack(push, 4)

#define WP7_DDHALINFO_FOURCC_RECORDS 0x00000001

#define WP7_DDHAL_CB32_CREATESURFACE    0x00000001
#define WP7_DDHAL_CB32_CANCREATESURFACE 0x00000002

#define WP7_DDHAL_SURFCB32_DESTROYSURFACE 0x00000001
#define WP7_DDHAL_SURFCB32_LOCK           0x00000002
#define WP7_DDHAL_SURFCB32_UNLOCK         0x00000004

#define WP7_STOCK_DRIVER_SURFACE_CAPS 0x00018184
#define WP7_STOCK_HEL_SURFACE_CAPS    0x00008080

#define WP7_DDSD_SURFACE_LAYOUT 0x03F8001F
#define WP7_SURFACE_ALIGN       32
#define WP7_PLANE_LAYOUT_DWORDS 6

#define WP7_FOURCC_NV12 0x3231564E
#define WP7_FOURCC_NV21 0x3132564E
#define WP7_FOURCC_YUYV 0x56595559
#define WP7_FOURCC_UYVY 0x59565955
#define WP7_FOURCC_YUY2 0x32595559
#define WP7_FOURCC_YV12 0x32315659
#define WP7_FOURCC_QTF1 0x31465451

#define WP7_CODE_YUYV 10
#define WP7_CODE_UYVY 11
#define WP7_CODE_YUY2 12
#define WP7_CODE_YV12 13
#define WP7_CODE_NV12 4097
#define WP7_CODE_NV21 4098
#define WP7_CODE_QTF1 4099

typedef struct _Wp7_FOURCC_FORMAT {
    DWORD dwFourCC;
    DWORD dwBitCount;
    DWORD dwYBitMask;
    DWORD dwUBitMask;
    DWORD dwVBitMask;
} Wp7_FOURCC_FORMAT;

typedef struct _Wp7_DDSURFACEDESC {
    DWORD             dwSize;
    DWORD             dwFlags;
    DWORD             dwHeight;
    DWORD             dwWidth;
    LONG              lPitch;
    LONG              lXPitch;
    DWORD             dwBackBufferCount;
    DWORD             dwRefreshRate;
    LPVOID            lpSurface;
    CerfDDCOLORKEY    ddckCKDestOverlay;
    CerfDDCOLORKEY    ddckCKDestBlt;
    CerfDDCOLORKEY    ddckCKSrcOverlay;
    CerfDDCOLORKEY    ddckCKSrcBlt;
    CerfDDPIXELFORMAT ddpfPixelFormat;
    CerfDDSCAPS       ddsCaps;
    DWORD             dwSurfaceSize;
    DWORD             dwPlaneLayout[WP7_PLANE_LAYOUT_DWORDS];
} Wp7_DDSURFACEDESC;

typedef struct _Wp7_DDCAPS {
    DWORD       dwSize;
    CerfDDSCAPS ddsCaps;
    DWORD       dwNumFourCCCodes;
    DWORD       dwBltCaps;
    DWORD       dwCKeyCaps;
    DWORD       dwRops[CERF_DD_ROP_SPACE];
} Wp7_DDCAPS;

typedef struct _Wp7_DDHAL_DDCALLBACKS {
    DWORD dwSize;
    DWORD dwFlags;
    PVOID CreateSurface;
    PVOID CanCreateSurface;
} Wp7_DDHAL_DDCALLBACKS;

typedef struct _Wp7_DDHAL_DDSURFACECALLBACKS {
    DWORD dwSize;
    DWORD dwFlags;
    PVOID DestroySurface;
    PVOID Lock;
    PVOID Unlock;
    PVOID SetColorKey;
} Wp7_DDHAL_DDSURFACECALLBACKS;

typedef struct _Wp7_DDHALINFO {
    DWORD      dwSize;
    DWORD      dwFlags;
    PVOID      lpDDCallbacks;
    PVOID      lpDDSurfaceCallbacks;
    PVOID      GetDriverInfo;
    Wp7_DDCAPS ddCaps;
    Wp7_DDCAPS ddHelCaps;
    PVOID      lpdwFourCC;
} Wp7_DDHALINFO;

typedef char Wp7_DDCAPS_IS_52_BYTES[(sizeof(Wp7_DDCAPS) == 52) ? 1 : -1];
typedef char Wp7_DDCALLBACKS_IS_16_BYTES[(sizeof(Wp7_DDHAL_DDCALLBACKS) == 16) ? 1 : -1];
typedef char Wp7_DDSURFACECALLBACKS_IS_24_BYTES[(sizeof(Wp7_DDHAL_DDSURFACECALLBACKS) == 24) ? 1 : -1];
typedef char Wp7_DDHALINFO_IS_128_BYTES[(sizeof(Wp7_DDHALINFO) == 128) ? 1 : -1];
typedef char Wp7_DDSURFACEDESC_IS_132_BYTES[(sizeof(Wp7_DDSURFACEDESC) == 132) ? 1 : -1];
typedef char Wp7_FOURCC_FORMAT_IS_20_BYTES[(sizeof(Wp7_FOURCC_FORMAT) == 20) ? 1 : -1];

#pragma pack(pop)
