#include <windows.h>
#include "cerf_wp7_yuv.h"
#include "cerfcore/lcd/qcom_tile_layout.h"
#include "cerfcore/peripherals/cerf_virt/cerf_virt_fb_regs.h"

#define CERF_WP7_ALIGN_PAGE        4096u
#define CERF_WP7_ALIGN_TILED_PLANE 8192u
#define CERF_WP7_TILED_META_BYTES  0x2000u
#define CERF_WP7_ALIGN_420_LUMA    64u
#define CERF_WP7_ALIGN_420_ROWS    64u
#define CERF_WP7_ALIGN_CHROMA      32u
#define CERF_WP7_ALIGN_PACKED      32u
#define CERF_WP7_PAD_ROWS          2u
#define CERF_WP7_LUMA_BLACK        16u
#define CERF_WP7_CHROMA_NEUTRAL    128u

#define CERF_WP7_CLASS_YUYV 6u
#define CERF_WP7_CLASS_UYVY 7u
#define CERF_WP7_CLASS_YV12 8u
#define CERF_WP7_CLASS_NV12 9u
#define CERF_WP7_CLASS_NV21 10u
#define CERF_WP7_CLASS_QTF1 11u
#define CERF_WP7_CLASS_NONE 12u

static const Wp7_FOURCC_FORMAT kCerfWp7FourCc[] = {
    { WP7_FOURCC_NV12, 12, 0xFFFFFFFFu, 0xFFFFFFFFu, 0xFFFFFFFFu },
    { WP7_FOURCC_NV21, 12, 0xFFFFFFFFu, 0xFFFFFFFFu, 0xFFFFFFFFu },
    { WP7_FOURCC_YUYV, 16, 0x00FF00FFu, 0x0000FF00u, 0xFF000000u },
    { WP7_FOURCC_UYVY, 16, 0xFF00FF00u, 0x000000FFu, 0x00FF0000u },
    { WP7_FOURCC_YUY2, 16, 0x00FF00FFu, 0x0000FF00u, 0xFF000000u },
    { WP7_FOURCC_YV12, 12, 0xFFFFFFFFu, 0xFFFFFFFFu, 0xFFFFFFFFu },
    { WP7_FOURCC_QTF1, 12, 0xFFFFFFFFu, 0xFFFFFFFFu, 0xFFFFFFFFu },
};

static DWORD CerfWp7AlignUp(DWORD v, DWORD a) { return (v + a - 1u) & ~(a - 1u); }

const Wp7_FOURCC_FORMAT* CerfWp7FourCcFormats(DWORD* count) {
    *count = sizeof(kCerfWp7FourCc) / sizeof(kCerfWp7FourCc[0]);
    return kCerfWp7FourCc;
}

static DWORD CerfWp7CodeOf(DWORD fourcc) {
    switch (fourcc) {
        case WP7_FOURCC_YUYV: return WP7_CODE_YUYV;
        case WP7_FOURCC_UYVY: return WP7_CODE_UYVY;
        case WP7_FOURCC_YUY2: return WP7_CODE_YUY2;
        case WP7_FOURCC_YV12: return WP7_CODE_YV12;
        case WP7_FOURCC_NV12: return WP7_CODE_NV12;
        case WP7_FOURCC_NV21: return WP7_CODE_NV21;
        case WP7_FOURCC_QTF1: return WP7_CODE_QTF1;
    }
    return 0;
}

BOOL CerfWp7YuvLayout(DWORD fourcc, DWORD w, DWORD h, CerfWp7Layout* l) {
    memset(l, 0, sizeof(*l));
    l->code = CerfWp7CodeOf(fourcc);
    if (l->code == 0) return FALSE;
    if (l->code == WP7_CODE_NV12 || l->code == WP7_CODE_NV21) {
        const DWORD s    = CerfWp7AlignUp(w, CERF_WP7_ALIGN_420_LUMA);
        const DWORD luma = CerfWp7AlignUp(CerfWp7AlignUp(h, CERF_WP7_ALIGN_420_ROWS) * s, CERF_WP7_ALIGN_PAGE);
        l->size          = luma + CerfWp7AlignUp(h >> 1, CERF_WP7_ALIGN_CHROMA) * s;
        l->stride        = s;
        l->cb_stride     = s;
        l->cr_stride     = s;
        l->cb_offset     = l->code == WP7_CODE_NV12 ? luma : luma + 1u;
        l->cr_offset     = l->code == WP7_CODE_NV12 ? luma + 1u : luma;
        l->xpitch        = 1u;
        l->chroma_xpitch = 2u;
    } else if (l->code == WP7_CODE_YV12) {
        const DWORD luma = CerfWp7AlignUp(CerfWp7AlignUp(h, CERF_WP7_ALIGN_420_ROWS) *
                                              CerfWp7AlignUp(w, CERF_WP7_ALIGN_420_LUMA),
                                          CERF_WP7_ALIGN_PAGE);
        const DWORD c       = CerfWp7AlignUp(w >> 1, CERF_WP7_ALIGN_CHROMA);
        const DWORD c_bytes = CerfWp7AlignUp(h >> 1, CERF_WP7_ALIGN_CHROMA) * c;
        l->size          = ((2u * (c_bytes + CERF_WP7_ALIGN_PAGE - 1u)) & ~(CERF_WP7_ALIGN_TILED_PLANE - 1u)) + luma;
        l->stride        = 2u * c;
        l->cb_stride     = c;
        l->cr_stride     = c;
        l->cr_offset     = luma;
        l->cb_offset     = luma + CerfWp7AlignUp(c_bytes, CERF_WP7_ALIGN_PAGE);
        l->xpitch        = 1u;
        l->chroma_xpitch = 1u;
    } else if (l->code == WP7_CODE_QTF1) {
        const DWORD s    = CerfWp7AlignUp(w, cerfcore::qcom_tile::kStrideAlign);
        const DWORD luma = CerfWp7AlignUp(CerfWp7AlignUp(h, cerfcore::qcom_tile::kHeight) * s,
                                          CERF_WP7_ALIGN_TILED_PLANE);
        l->size          = CerfWp7AlignUp(CerfWp7AlignUp(h >> 1, cerfcore::qcom_tile::kHeight) * s,
                                          CERF_WP7_ALIGN_TILED_PLANE) + luma + CERF_WP7_TILED_META_BYTES;
        l->stride        = s;
        l->cb_stride     = s;
        l->cr_stride     = s;
        l->cb_offset     = luma;
        l->cr_offset     = luma + 1u;
        l->xpitch        = 1u;
        l->chroma_xpitch = 2u;
    } else {
        l->stride = CerfWp7AlignUp(w, CERF_WP7_ALIGN_PACKED) * 2u;
        l->size   = CerfWp7AlignUp(h, CERF_WP7_ALIGN_PACKED) * l->stride;
        l->xpitch = 2u;
    }
    return TRUE;
}

void CerfWp7DescribeLayout(Wp7_DDSURFACEDESC* d, const CerfWp7Layout* l) {
    d->dwFlags         |= WP7_DDSD_SURFACE_LAYOUT;
    d->lPitch           = (LONG)l->stride;
    d->lXPitch          = (LONG)l->xpitch;
    d->dwSurfaceSize    = l->size;
    d->dwPlaneLayout[0] = l->cb_stride;
    d->dwPlaneLayout[1] = l->chroma_xpitch;
    d->dwPlaneLayout[2] = l->cb_offset;
    d->dwPlaneLayout[3] = l->cr_stride;
    d->dwPlaneLayout[4] = l->chroma_xpitch;
    d->dwPlaneLayout[5] = l->cr_offset;
}

ULONG CerfWp7OverlayFormat(DWORD code) {
    switch (code) {
        case WP7_CODE_YUYV:
        case WP7_CODE_YUY2: return cerfcore::CerfVirt::kFbOverlayYuyv;
        case WP7_CODE_UYVY: return cerfcore::CerfVirt::kFbOverlayUyvy;
        case WP7_CODE_YV12: return cerfcore::CerfVirt::kFbOverlayYuv420Planar;
        case WP7_CODE_NV12:
        case WP7_CODE_NV21: return cerfcore::CerfVirt::kFbOverlayYuv420SemiPlanar;
        case WP7_CODE_QTF1: return cerfcore::CerfVirt::kFbOverlayYuv420SemiPlanarTiled;
    }
    return 0;
}

ULONG CerfWp7DescClass(DWORD code) {
    switch (code) {
        case WP7_CODE_YUYV:
        case WP7_CODE_YUY2: return CERF_WP7_CLASS_YUYV;
        case WP7_CODE_UYVY: return CERF_WP7_CLASS_UYVY;
        case WP7_CODE_YV12: return CERF_WP7_CLASS_YV12;
        case WP7_CODE_NV12: return CERF_WP7_CLASS_NV12;
        case WP7_CODE_NV21: return CERF_WP7_CLASS_NV21;
        case WP7_CODE_QTF1: return CERF_WP7_CLASS_QTF1;
    }
    return CERF_WP7_CLASS_NONE;
}

static void CerfWp7PadRegion(BYTE* luma, BYTE* chroma, DWORD cols, DWORD luma_rows, DWORD chroma_rows,
                             DWORD x0, DWORD x1, DWORD y0, DWORD y1) {
    DWORD x, y;
    if (y0 >= y1 || x0 >= x1) return;
    for (y = y0; y < y1; ++y)
        for (x = x0; x < x1; ++x)
            luma[cerfcore::qcom_tile::Offset(x, y, cols, luma_rows)] = (BYTE)CERF_WP7_LUMA_BLACK;
    for (y = y0 >> 1; y < (y1 + 1u) >> 1; ++y)
        for (x = x0; x < x1 + (x1 & 1u); ++x)
            chroma[cerfcore::qcom_tile::Offset(x, y, cols, chroma_rows)] = (BYTE)CERF_WP7_CHROMA_NEUTRAL;
}

void CerfWp7PadTiled(BYTE* luma, DWORD chroma_offset, DWORD w, DWORD h) {
    const DWORD aw   = CerfWp7AlignUp(w, cerfcore::qcom_tile::kStrideAlign);
    const DWORD ah   = CerfWp7AlignUp(h, cerfcore::qcom_tile::kHeight);
    const DWORD ach  = CerfWp7AlignUp((h + 1u) >> 1, cerfcore::qcom_tile::kHeight);
    const DWORD cols = cerfcore::qcom_tile::Columns(aw);
    const DWORD rows = cerfcore::qcom_tile::Rows(ah);
    const DWORD crow = cerfcore::qcom_tile::Rows(ach);
    BYTE* const chroma = luma + chroma_offset;
    DWORD right = CerfWp7AlignUp(w, cerfcore::qcom_tile::kWidth);
    if (w >= right || w + CERF_WP7_PAD_ROWS <= right) right = w + CERF_WP7_PAD_ROWS;
    if (right > aw) right = aw;
    CerfWp7PadRegion(luma, chroma, cols, rows, crow, 0u, aw, h,
                     (h + CERF_WP7_PAD_ROWS < ah) ? h + CERF_WP7_PAD_ROWS : ah);
    CerfWp7PadRegion(luma, chroma, cols, rows, crow, w, right, 0u, ah);
}
