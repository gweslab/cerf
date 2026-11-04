#include <windows.h>
#include <winddi.h>

#include "include/cerf_gpe.h"

int CerfEGPEFormatBpp(EGPEFormat fmt) {
    switch (fmt) {
    case gpe1Bpp:  return 1;
    case gpe2Bpp:  return 2;
    case gpe4Bpp:  return 4;
    case gpe8Bpp:  return 8;
    case gpe16Bpp: return 16;
    case gpe24Bpp: return 24;
    case gpe32Bpp: return 32;
    default:       return 32;
    }
}

EGPEFormat CerfEGPEFormatOfBpp(ULONG bpp) {
    switch (bpp) {
    case 1:  return gpe1Bpp;
    case 2:  return gpe2Bpp;
    case 4:  return gpe4Bpp;
    case 8:  return gpe8Bpp;
    case 16: return gpe16Bpp;
    case 24: return gpe24Bpp;
    case 32: return gpe32Bpp;
    default: return gpeUndefined;
    }
}

int CerfEGPEFormatStride(int width, EGPEFormat fmt) {
    return ((CerfEGPEFormatBpp(fmt) * width + 31) >> 5) << 2;
}

EGPEFormat CerfIFormatToEGPE(ULONG iFormat) {
    static const EGPEFormat table[10] = {
        gpeDeviceCompatible, gpe1Bpp, gpe4Bpp, gpe8Bpp, gpe16Bpp,
        gpe24Bpp, gpe32Bpp, gpeUndefined, gpeUndefined, gpe2Bpp
    };
    return (iFormat < 10) ? table[iFormat] : gpeUndefined;
}

ULONG CerfEGPEToIFormat(EGPEFormat fmt) {
    switch (fmt) {
    case gpe1Bpp:  return BMF_1BPP;
    case gpe2Bpp:  return BMF_2BPP;
    case gpe4Bpp:  return BMF_4BPP;
    case gpe8Bpp:  return BMF_8BPP;
    case gpe16Bpp: return BMF_16BPP;
    case gpe24Bpp: return BMF_24BPP;
    case gpe32Bpp: return BMF_32BPP;
    default:       return 0;
    }
}

void GPESurf::Init(int width, int height, void* pBits, int stride, EGPEFormat format) {
    m_Format.m_pPalette       = NULL;
    m_Format.m_PaletteEntries = 0;
    m_Format.m_OwnsPalette    = FALSE;
    m_Format.m_iUniq          = 0;
    m_pVirtAddr            = (ADDRESS)pBits;
    m_nStrideBytes         = (ULONG)stride;
    m_eFormat              = format;
    m_fInVideoMemory       = 0;
    m_fInUserMemory        = FALSE;
    m_nWidth               = width;
    m_nHeight              = height;
    m_nOffsetInVideoMemory = 0;
    m_iRotate              = DMDO_0;
    m_ScreenWidth          = width;
    m_ScreenHeight         = height;
    m_BytesPixel           = CerfEGPEFormatBpp(format) / 8;
    m_nHandle              = 0;
}

GPESurf::~GPESurf() {}

extern "C" HLOCAL RemoteLocalAlloc(UINT uFlags, UINT uBytes);
extern "C" HLOCAL RemoteLocalFree(HLOCAL hMem);

DDGPESurf::DDGPESurf(int width, int height, EGPEFormat format)
    : GPESurf(width, height, NULL, CerfEGPEFormatStride(width, format), format),
      m_pixelFormat(CerfFormatToDDGPE(format)),
      m_colorKeyLow(0), m_colorKeyHigh(0), m_ownsRemote(0) {
    const DWORD bytes = (DWORD)CerfEGPEFormatStride(width, format) * (DWORD)height;
    if (bytes) {
        m_pVirtAddr  = (ADDRESS)RemoteLocalAlloc(LMEM_FIXED, bytes);
        m_ownsRemote = 1;
    }
}

DDGPESurf::~DDGPESurf() {
    if (m_ownsRemote && m_pVirtAddr) {
        RemoteLocalFree((void*)m_pVirtAddr);
        m_pVirtAddr = 0;
    }
}

SurfaceHeap::SurfaceHeap(ULONG size, ULONG base)
    : m_head(NULL), m_next(NULL), m_address(base), m_size(size), m_used(0),
      m_isRoot(1) {
}

SurfaceHeap::~SurfaceHeap() {
    if (!m_isRoot) return;
    SurfaceHeap* n = m_next;
    while (n) {
        SurfaceHeap* next = n->m_next;
        delete n;
        n = next;
    }
    m_next = NULL;
}

SurfaceHeap* SurfaceHeap::Alloc(ULONG bytes) {
    const ULONG want = (bytes + 3u) & ~3u;
    if (want == 0) return NULL;

    for (SurfaceHeap* n = this; n; n = n->m_next) {
        if (n->m_used || n->m_size < want) continue;
        if (n->m_size > want) {
            SurfaceHeap* rest = new SurfaceHeap(n->m_size - want, n->m_address + want);
            if (!rest) return NULL;
            rest->m_isRoot = 0;
            rest->m_head   = this;
            rest->m_next   = n->m_next;
            n->m_next      = rest;
            n->m_size      = want;
        }
        n->m_used = 1;
        n->m_head = this;
        return n;
    }
    return NULL;
}

void SurfaceHeap::Free() {
    m_used = 0;
    SurfaceHeap* root = m_head ? m_head : this;
    for (SurfaceHeap* n = root; n; n = n->m_next) {
        while (n->m_next && !n->m_used && !n->m_next->m_used) {
            SurfaceHeap* dead = n->m_next;
            n->m_size += dead->m_size;
            n->m_next  = dead->m_next;
            delete dead;
        }
    }
}

ULONG SurfaceHeap::Available() {
    ULONG free_bytes = 0;
    for (SurfaceHeap* n = this; n; n = n->m_next) {
        if (!n->m_used) free_bytes += n->m_size;
    }
    return free_bytes;
}

GPE::GPE()
    : m_pPrimarySurface(NULL), m_pMode(NULL), m_nScreenWidth(0), m_nScreenHeight(0),
      m_hSurf(0) {
}

GPE::~GPE() {
    if (m_pPrimarySurface) {
        delete m_pPrimarySurface;
        m_pPrimarySurface = NULL;
    }
}

SCODE GPE::EmulatedBlt(GPEBltParms* pParms) {
    CERF_LOG_X("cerf_guest: EmulatedBlt (software raster) reached, rop4",
               pParms ? pParms->rop4 : 0);
    CERF_FATAL("cerf_guest: software raster is not a supported path - halting");
    return E_FAIL;
}

SCODE GPE::EmulatedLine(GPELineParms* pParms) {
    CERF_LOG_X("cerf_guest: EmulatedLine (software raster) reached, mix",
               pParms ? pParms->mix : 0);
    CERF_FATAL("cerf_guest: software raster is not a supported path - halting");
    return E_FAIL;
}

void CerfRequireExtent(int v, int who) {
    if (v > 0) return;
    CERF_LOG_X("cerf_guest: extent owner", (ULONG)who);
    CERF_LOG_X("cerf_guest: reported extent", (ULONG)v);
    CERF_FATAL("cerf_guest: surface reports no extent - halting");
}

void CerfRectClamp(RECTL* r, const RECTL* bound) {
    if (bound->left   > r->left)   r->left   = bound->left;
    if (bound->top    > r->top)    r->top    = bound->top;
    if (bound->right  < r->right)  r->right  = bound->right;
    if (bound->bottom < r->bottom) r->bottom = bound->bottom;
}

void CerfEffectiveClip(RECTL* out, const RECTL* clip, GPESurf* dst) {
    CerfRequireExtent(dst->Width(), kCerfExtentDstWidth);
    CerfRequireExtent(dst->Height(), kCerfExtentDstHeight);
    const LONG w = (LONG)dst->Width();
    const LONG h = (LONG)dst->Height();
    out->left   = 0;
    out->top    = 0;
    out->right  = w;
    out->bottom = h;
    if (clip) CerfRectClamp(out, clip);
}

SCODE GPE::BltExpanded(GPESurf* pDst, GPESurf* pSrc, GPESurf* pPattern,
                       const RECT* prclDst, const RECT* prclSrc, ULONG solidColor,
                       ULONG bltFlags, ULONG rop4) {
    GPEBltParms parms;
    memset(&parms, 0, sizeof(parms));
    parms.pDst       = pDst;
    parms.pSrc       = pSrc;
    parms.pBrush     = pPattern;
    parms.prclDst    = (RECTL*)prclDst;
    parms.prclSrc    = (RECTL*)prclSrc;
    parms.solidColor = (COLOR)solidColor;
    parms.bltFlags   = bltFlags;
    parms.rop4       = (ROP4)rop4;
    parms.xPositive  = 1;
    parms.yPositive  = 1;
    parms.blendFunction.SourceConstantAlpha = 0xFF;

    SCODE sc = BltPrepare(&parms);
    if (FAILED(sc)) return sc;
    sc = (this->*parms.pBlt)(&parms);
    if (FAILED(sc)) return sc;
    return BltComplete(&parms);
}

SCODE GPE::SetPalette(const PALETTEENTRY*, unsigned short, unsigned short) {
    return S_OK;
}

SCODE GPE::GetPalette(PALETTEENTRY** ppPalette, unsigned short* pcEntries) {
    if (ppPalette) *ppPalette = NULL;
    if (pcEntries) *pcEntries = 0;
    return S_OK;
}

void GPE::SetVisibleSurface(GPESurf*, BOOL) {
}

ULONG GPE::GetGraphicsCaps() {
    return 0;
}

BOOL GPE::IsPaletteSettable() {
    return m_pMode && m_pMode->Bpp == 8;
}

BOOL GPE::GetScreenDimensions(GPEScreenProps*) {
    return FALSE;
}

ULONG* GPE::GetClearTypeRGBMasks() {
    return NULL;
}

ULONG GPE::DrvEscape(SURFOBJ*, ULONG, ULONG, PVOID, ULONG, PVOID) {
    return 0;
}

#define CERF_DDRAW_LCL_DRIVER_SLOT 0x10

void DDGPESurf::SetDDGPESurf(LPDDRAWI_DDRAWSURFACE_LCL lcl) {
    if (!lcl) return;
    *(ULONG_PTR*)((BYTE*)lcl + CERF_DDRAW_LCL_DRIVER_SLOT) = (ULONG_PTR)this;
}

DDGPESurf* DDGPESurf::GetDDGPESurf(LPDDRAWI_DDRAWSURFACE_LCL lcl) {
    if (!lcl) return NULL;
    return (DDGPESurf*)*(ULONG_PTR*)((BYTE*)lcl + CERF_DDRAW_LCL_DRIVER_SLOT);
}
