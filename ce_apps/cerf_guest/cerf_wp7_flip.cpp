#include <windows.h>
#include "cerf_wp7_flip.h"
#include "cerf_ddgpe.h"
#include "cerf_debug_log.h"
#include "cerf_wp7_coredll.h"
#include "cerf_wp7_yuv.h"
#include "main.h"
#include "cerfcore/lcd/qcom_tile_layout.h"
#include "cerfcore/peripherals/cerf_virt/cerf_virt_fb_regs.h"

#define CERF_WP7_FLIP_DISPLAYS      32
#define CERF_WP7_ROP4_SRCCOPY       0xCCCC

#define CERF_WP7_REC_SURFACE_A      0
#define CERF_WP7_REC_DIRTY_A        1
#define CERF_WP7_REC_SURFACE_B      2
#define CERF_WP7_REC_SRC_RECT       3
#define CERF_WP7_REC_DST_RECT       7
#define CERF_WP7_REC_ROTATION       11
#define CERF_WP7_REC_FILTER         12

#define CERF_WP7_QSEED_PAIRS        15
#define CERF_WP7_SCALE_CLASSES      5
#define CERF_WP7_SCALE_CLASS_SKIP   5u
#define CERF_WP7_FILTER_WORDS       3u
#define CERF_WP7_REC_DIRTY_B        13
#define CERF_WP7_REC_LAYERS         14
#define CERF_WP7_REC_SWAP_INTERVAL  15

#define CERF_WP7_DXGI_ROTATE90      2
#define CERF_WP7_DXGI_ROTATE180     3
#define CERF_WP7_DXGI_ROTATE270     4

#define CERF_WP7_META_RESERVE       0x2000u
#define CERF_WP7_META_MAGIC         0x0DEC0DE0u
#define CERF_WP7_META_LUMA_STRIDE   0
#define CERF_WP7_META_CHROMA_STRIDE 1
#define CERF_WP7_META_CHROMA_OFFSET 2
#define CERF_WP7_META_CROP          3
#define CERF_WP7_META_MAGIC_WORD    8
#define CERF_WP7_META_SAVED         9
#define CERF_WP7_META_SAVED_CROP    12
#define CERF_WP7_META_PAD_BYTE      28
#define CERF_WP7_META_SAVED_BYTES   36

typedef struct {
    ULONG format, width, height, pa, stride, cb, cr, chroma_stride;
    ULONG rect[4];
} CerfWp7Plane;

#define CERF_WP7_LAYERS_A           0
#define CERF_WP7_LAYERS_B           1
#define CERF_WP7_LAYERS_BOTH        2

#define CERF_WP7_MS_PER_SECOND      1000u

static BOOL   g_Wp7Flipping[CERF_WP7_FLIP_DISPLAYS];
static HANDLE g_Wp7FreeBuffer;
static DWORD  g_Wp7ShownAt;
static DWORD  g_Wp7SwapInterval;
static DWORD  g_Wp7RefreshOrigin;
static BOOL   g_Wp7FullScreenHanded;

static HANDLE CerfWp7FreeBuffer(void) {
    if (!g_Wp7FreeBuffer) g_Wp7FreeBuffer = CerfWp7Api()->create_semaphore(NULL, 0, 1, NULL);
    if (!g_Wp7FreeBuffer) CERF_FATAL("cerf_guest: WP7 free-buffer semaphore creation failed - halting");
    return g_Wp7FreeBuffer;
}

static int CerfWp7TakeLayerChange(const DWORD* record, int surface, int dirty) {
    DDGPESurf* s = (DDGPESurf*)record[surface];
    if (!s) return 1;
    return (s->TakeModified() || record[dirty]) ? 1 : 0;
}

static void CerfWp7PresentLayerA(DDGPESurf* surface) {
    if (!surface) CERF_FATAL("cerf_guest: WP7 flip of an empty layer A is not implemented - halting");
    if (surface->PhysicalAddress()) {
        CerfSetScanoutLayer(surface->PhysicalAddress(), (ULONG)surface->Width(),
                            (ULONG)surface->Height(), (ULONG)surface->Stride(),
                            (ULONG)CerfFormatBpp(surface->Format()));
        return;
    }
    CerfSetScanoutLayer(0, 0, 0, 0, 0);
    CerfDDGPE* gpe = (CerfDDGPE*)GetGPE();
    if (surface->InVideoMemory()) {
        gpe->SetVisibleSurface(surface, FALSE);
        return;
    }
    GPESurf* screen = gpe->PrimarySurface();
    RECT     r;
    r.left   = 0;
    r.top    = 0;
    r.right  = (surface->Width()  < screen->Width())  ? surface->Width()  : screen->Width();
    r.bottom = (surface->Height() < screen->Height()) ? surface->Height() : screen->Height();
    if (FAILED(gpe->BltExpanded(screen, surface, NULL, &r, &r, 0, 0, CERF_WP7_ROP4_SRCCOPY)))
        CERF_FATAL("cerf_guest: WP7 layer A present failed - halting");
    gpe->SetVisibleSurface(screen, FALSE);
}

static ULONG CerfWp7Align(ULONG v, ULONG a) { return (v + a - 1u) & ~(a - 1u); }

static ULONG CerfWp7RgbOverlayFormat(EGPEFormat format) {
    switch (format) {
        case gpe16Bpp: return cerfcore::CerfVirt::kFbOverlayRgb565;
        case gpe24Bpp: return cerfcore::CerfVirt::kFbOverlayRgb888;
        case gpe32Bpp: return cerfcore::CerfVirt::kFbOverlayArgb8888;
        default: break;
    }
    CERF_LOG_X("cerf_guest: WP7 layer B surface format", (ULONG)format);
    CERF_FATAL("cerf_guest: WP7 layer B surface format is not implemented - halting");
    return 0;
}

static void CerfWp7TiledMeta(DDGPESurf* s, CerfWp7Plane* p) {
    DWORD* meta = (DWORD*)((BYTE*)s->Buffer() + s->SurfaceBytes() - CERF_WP7_META_RESERVE);
    p->width  = CerfWp7Align((ULONG)s->Width(), cerfcore::qcom_tile::kStrideAlign);
    p->height = CerfWp7Align((ULONG)s->Height(), cerfcore::qcom_tile::kHeight);
    if (meta[CERF_WP7_META_MAGIC_WORD] != CERF_WP7_META_MAGIC) {
        p->cb = p->width * p->height;
        p->cr = p->cb + 1u;
        return;
    }
    const DWORD crop_w = meta[CERF_WP7_META_CROP + 2] - meta[CERF_WP7_META_CROP];
    const DWORD crop_h = meta[CERF_WP7_META_CROP + 3] - meta[CERF_WP7_META_CROP + 1];
    BYTE* const pad    = (BYTE*)meta + CERF_WP7_META_PAD_BYTE;
    if (meta[CERF_WP7_META_SAVED_CROP + 2] - meta[CERF_WP7_META_SAVED_CROP] == crop_w &&
        meta[CERF_WP7_META_SAVED_CROP + 3] - meta[CERF_WP7_META_SAVED_CROP + 1] == crop_h) {
        if (*pad == 1u) {
            CerfWp7PadTiled((BYTE*)s->Buffer(), meta[CERF_WP7_META_CHROMA_OFFSET], crop_w, crop_h);
            *pad = 0u;
        }
    } else {
        *pad = 0u;
        CerfWp7PadTiled((BYTE*)s->Buffer(), meta[CERF_WP7_META_CHROMA_OFFSET], crop_w, crop_h);
        memcpy(meta + CERF_WP7_META_SAVED, meta, CERF_WP7_META_SAVED_BYTES);
    }
    if (p->rect[0] < meta[CERF_WP7_META_CROP]) p->rect[0] = meta[CERF_WP7_META_CROP];
    if (p->rect[1] < meta[CERF_WP7_META_CROP + 1]) p->rect[1] = meta[CERF_WP7_META_CROP + 1];
    if (p->rect[2] > meta[CERF_WP7_META_CROP + 2]) p->rect[2] = meta[CERF_WP7_META_CROP + 2];
    if (p->rect[3] > meta[CERF_WP7_META_CROP + 3]) p->rect[3] = meta[CERF_WP7_META_CROP + 3];
    p->stride        = meta[CERF_WP7_META_LUMA_STRIDE];
    p->cb            = meta[CERF_WP7_META_CHROMA_OFFSET];
    p->cr            = p->cb + 1u;
    p->chroma_stride = meta[CERF_WP7_META_CHROMA_STRIDE];
    p->width         = CerfWp7Align(crop_w, cerfcore::qcom_tile::kStrideAlign);
    p->height        = CerfWp7Align(crop_h, cerfcore::qcom_tile::kHeight);
}

static const DWORD kCerfWp7QseedSelect[CERF_WP7_QSEED_PAIRS][2] = {
    { 0x00000000u, 0x20000000u }, { 0x22222222u, 0x22222222u }, { 0x33333333u, 0x33333333u },
    { 0x44444444u, 0x44444444u }, { 0x55555555u, 0x55555555u }, { 0x66666666u, 0x66666666u },
    { 0x77777777u, 0x77777777u }, { 0x88888888u, 0x88888888u }, { 0x99999999u, 0x09999999u },
    { 0xAAAAAAAAu, 0x0AAAAAAAu }, { 0xBBBBBBBBu, 0x0BBBBBBBu }, { 0xCCCCCCCCu, 0x0CCCCCCCu },
    { 0xDDDDDDDDu, 0x0DDDDDDDu }, { 0xEEEEEEEEu, 0x0EEEEEEEu }, { 0xFFFFFFFFu, 0x0FFFFFFFu },
};

static const DWORD kCerfWp7ClassPair[CERF_WP7_SCALE_CLASSES] = { 0u, 1u, 4u, 5u, 7u };

static DWORD g_Wp7SelectPair;

static DWORD CerfWp7ScaleClass(DWORD src, DWORD dst) {
    if (dst >= src) return 0u;
    if (5u * dst >= 4u * src) return 1u;
    if (5u * dst >= 3u * src) return 2u;
    if (5u * dst >= 2u * src) return 3u;
    if (4u * dst < src) return CERF_WP7_SCALE_CLASS_SKIP;
    return 4u;
}

static const DWORD kCerfWp7FilterLevel[CERF_WP7_FILTER_WORDS] = { 0u, 14u, 7u };

static DWORD CerfWp7FilterLevel(DWORD filter) {
    return filter < CERF_WP7_FILTER_WORDS ? kCerfWp7FilterLevel[filter] : 0u;
}

static void CerfWp7UpdateSelect(DWORD src_w, DWORD src_h, DWORD dst_w, DWORD dst_h, DWORD filter) {
    DWORD scale_class = CerfWp7ScaleClass(src_w, dst_w);
    if (scale_class == 0u || scale_class == CERF_WP7_SCALE_CLASS_SKIP) {
        const DWORD by_height = CerfWp7ScaleClass(src_h, dst_h);
        if (by_height != CERF_WP7_SCALE_CLASS_SKIP) scale_class = by_height;
    }
    if (scale_class == CERF_WP7_SCALE_CLASS_SKIP) return;
    g_Wp7SelectPair = scale_class ? kCerfWp7ClassPair[scale_class] : CerfWp7FilterLevel(filter);
}

static ULONG CerfWp7Clockwise(DWORD dxgi_rotation) {
    switch (dxgi_rotation) {
        case CERF_WP7_DXGI_ROTATE90:  return 3u;
        case CERF_WP7_DXGI_ROTATE180: return 2u;
        case CERF_WP7_DXGI_ROTATE270: return 1u;
    }
    return 0u;
}

static void CerfWp7PresentLayerB(DDGPESurf* s, const DWORD* record, ULONG layers) {
    if (!s) CERF_FATAL("cerf_guest: WP7 flip of an empty layer B is not implemented - halting");
    CerfWp7Plane p;
    ULONG        i;
    memset(&p, 0, sizeof(p));
    p.pa = s->PhysicalAddress();
    if (!p.pa && !((CerfDDGPE*)GetGPE())->SurfaceFbPa(s, &p.pa)) p.pa = 0;
    if (!p.pa) CERF_FATAL("cerf_guest: WP7 layer B surface has no physical address - halting");
    for (i = 0; i < 4u; ++i) p.rect[i] = record[CERF_WP7_REC_SRC_RECT + i];
    p.width         = (ULONG)s->Width();
    p.height        = (ULONG)s->Height();
    p.stride        = (ULONG)s->Stride();
    p.cb            = s->CbOffset();
    p.cr            = s->CrOffset();
    p.chroma_stride = s->ChromaStride();
    p.format        = s->YuvCode() ? CerfWp7OverlayFormat(s->YuvCode()) : CerfWp7RgbOverlayFormat(s->Format());
    if (s->YuvCode() == WP7_CODE_QTF1) CerfWp7TiledMeta(s, &p);
    CerfWriteFbReg(cerfcore::CerfVirt::kFbRegOverlayFormat, p.format);
    CerfWriteFbReg(cerfcore::CerfVirt::kFbRegOverlayWidth, p.width);
    CerfWriteFbReg(cerfcore::CerfVirt::kFbRegOverlayHeight, p.height);
    CerfWriteFbReg(cerfcore::CerfVirt::kFbRegOverlayPa, p.pa);
    CerfWriteFbReg(cerfcore::CerfVirt::kFbRegOverlayStride, p.stride);
    CerfWriteFbReg(cerfcore::CerfVirt::kFbRegOverlayCbOffset, p.cb);
    CerfWriteFbReg(cerfcore::CerfVirt::kFbRegOverlayCrOffset, p.cr);
    CerfWriteFbReg(cerfcore::CerfVirt::kFbRegOverlayChromaStride, p.chroma_stride);
    CerfWriteFbReg(cerfcore::CerfVirt::kFbRegOverlaySrcLeft, p.rect[0]);
    CerfWriteFbReg(cerfcore::CerfVirt::kFbRegOverlaySrcTop, p.rect[1]);
    CerfWriteFbReg(cerfcore::CerfVirt::kFbRegOverlaySrcRight, p.rect[2]);
    CerfWriteFbReg(cerfcore::CerfVirt::kFbRegOverlaySrcBottom, p.rect[3]);
    CerfWriteFbReg(cerfcore::CerfVirt::kFbRegOverlayDstLeft, record[CERF_WP7_REC_DST_RECT]);
    CerfWriteFbReg(cerfcore::CerfVirt::kFbRegOverlayDstTop, record[CERF_WP7_REC_DST_RECT + 1]);
    CerfWriteFbReg(cerfcore::CerfVirt::kFbRegOverlayDstRight, record[CERF_WP7_REC_DST_RECT + 2]);
    CerfWriteFbReg(cerfcore::CerfVirt::kFbRegOverlayDstBottom, record[CERF_WP7_REC_DST_RECT + 3]);
    const ULONG clockwise = CerfWp7Clockwise(record[CERF_WP7_REC_ROTATION]);
    const DWORD src_w     = p.rect[2] - p.rect[0];
    const DWORD src_h     = p.rect[3] - p.rect[1];
    CerfWp7UpdateSelect((clockwise & 1u) ? src_h : src_w, (clockwise & 1u) ? src_w : src_h,
                        record[CERF_WP7_REC_DST_RECT + 2] - record[CERF_WP7_REC_DST_RECT],
                        record[CERF_WP7_REC_DST_RECT + 3] - record[CERF_WP7_REC_DST_RECT + 1],
                        record[CERF_WP7_REC_FILTER]);
    CerfWriteFbReg(cerfcore::CerfVirt::kFbRegOverlayClockwise, clockwise);
    CerfWriteFbReg(cerfcore::CerfVirt::kFbRegOverlaySelectX, kCerfWp7QseedSelect[g_Wp7SelectPair][0]);
    CerfWriteFbReg(cerfcore::CerfVirt::kFbRegOverlaySelectY, kCerfWp7QseedSelect[g_Wp7SelectPair][1]);
    CerfWriteFbReg(cerfcore::CerfVirt::kFbRegOverlayLayers, layers);
}

static DWORD CerfWp7RefreshDue(DWORD shown_ms, DWORD refreshes) {
    const DWORD rate    = g_FbRefreshRate;
    DWORD       elapsed = shown_ms - g_Wp7RefreshOrigin;
    g_Wp7RefreshOrigin += (elapsed / CERF_WP7_MS_PER_SECOND) * CERF_WP7_MS_PER_SECOND;
    elapsed = shown_ms - g_Wp7RefreshOrigin;
    const DWORD frame = elapsed * rate / CERF_WP7_MS_PER_SECOND + refreshes;
    return g_Wp7RefreshOrigin + (frame * CERF_WP7_MS_PER_SECOND + rate - 1) / rate;
}

extern "C" VOID CerfWp7FullScreenSurface(SURFOBJ* pso) {
    CERF_LOG_X_DEV("cerf_guest: WP7 full-screen surface dhsurf", (ULONG)pso->dhsurf);
    if (g_Wp7FullScreenHanded) return;
    DDGPESurf* s = (DDGPESurf*)pso->dhsurf;
    if (!s) CERF_FATAL("cerf_guest: WP7 full-screen surface without a driver surface is not implemented - halting");
    GPESurf*         primary = GetGPE()->PrimarySurface();
    const EGPEFormat format  = s->Format();
    if ((format != gpe16Bpp && format != gpe24Bpp && format != gpe32Bpp) ||
        s->Width() != primary->Width() || s->Height() != primary->Height())
        return;
    g_Wp7FullScreenHanded = TRUE;
    CerfWp7PresentLayerA(s);
}

extern "C" int InitializeFlipping(DWORD display) {
    const USHORT id = (USHORT)display;
    CERF_LOG_X_DEV("cerf_guest: WP7 InitializeFlipping display", id);
    if (id >= CERF_WP7_FLIP_DISPLAYS) CERF_FATAL("cerf_guest: WP7 flip display id out of range - halting");
    g_Wp7Flipping[id] = TRUE;
    return 0;
}

extern "C" int TerminateFlipping(DWORD display) {
    const USHORT id = (USHORT)display;
    CERF_LOG_X_DEV("cerf_guest: WP7 TerminateFlipping display", id);
    if (id >= CERF_WP7_FLIP_DISPLAYS) CERF_FATAL("cerf_guest: WP7 flip display id out of range - halting");
    g_Wp7Flipping[id] = FALSE;
    return 0;
}

extern "C" int ScreenUpdateByFlipEx(DWORD display, const DWORD* record) {
    const USHORT id     = (USHORT)display;
    const DWORD  layers = record[CERF_WP7_REC_LAYERS];
    int          changed = 0;
    if (layers == CERF_WP7_LAYERS_A || layers == CERF_WP7_LAYERS_BOTH)
        changed = CerfWp7TakeLayerChange(record, CERF_WP7_REC_SURFACE_A, CERF_WP7_REC_DIRTY_A);
    if (layers == CERF_WP7_LAYERS_B || layers == CERF_WP7_LAYERS_BOTH)
        changed |= CerfWp7TakeLayerChange(record, CERF_WP7_REC_SURFACE_B, CERF_WP7_REC_DIRTY_B);
    if (id >= CERF_WP7_FLIP_DISPLAYS || !g_Wp7Flipping[id]) return changed;

    if (layers > CERF_WP7_LAYERS_BOTH) {
        CERF_LOG_X("cerf_guest: WP7 flip layer selector", layers);
        CERF_FATAL("cerf_guest: WP7 flip layer selector is not implemented - halting");
    }
    if (layers != CERF_WP7_LAYERS_B) CerfWp7PresentLayerA((DDGPESurf*)record[CERF_WP7_REC_SURFACE_A]);
    if (layers == CERF_WP7_LAYERS_A)
        CerfWriteFbReg(cerfcore::CerfVirt::kFbRegOverlayLayers, cerfcore::CerfVirt::kFbOverlayLayersBase);
    else
        CerfWp7PresentLayerB((DDGPESurf*)record[CERF_WP7_REC_SURFACE_B], record,
                             layers == CERF_WP7_LAYERS_B ? cerfcore::CerfVirt::kFbOverlayLayersOverlay
                                                         : cerfcore::CerfVirt::kFbOverlayLayersBoth);
    g_Wp7FullScreenHanded = FALSE;
    g_Wp7ShownAt          = GetTickCount();
    g_Wp7SwapInterval     = record[CERF_WP7_REC_SWAP_INTERVAL];
    CerfWp7Api()->release_semaphore(CerfWp7FreeBuffer(), 1, NULL);
    return changed;
}

extern "C" DWORD ClaimFreeBuffer(DWORD display) {
    const USHORT id = (USHORT)display;
    if (id >= CERF_WP7_FLIP_DISPLAYS || !g_Wp7Flipping[id]) return id;
    const DWORD rc     = WaitForSingleObject(CerfWp7FreeBuffer(), INFINITE);
    const DWORD due    = CerfWp7RefreshDue(g_Wp7ShownAt,
                                           g_Wp7SwapInterval > 1 ? g_Wp7SwapInterval : 1);
    const LONG  remain = (LONG)(due - GetTickCount());
    if (remain > 0) Sleep((DWORD)remain);
    return rc;
}

extern "C" int SetSurfaceModified(void* surface) {
    if (surface) ((DDGPESurf*)surface)->MarkModified();
    return (int)surface;
}
