#include "cerf_ddgpe.h"
#include "cerf_eng_callbacks.h"
#include "main.h"

#ifndef DMDO_0
#define DMDO_0 0
#endif

class CerfVidSurf : public DDGPESurf {
public:
    CerfVidSurf(int w, int h, void* pBits, int stride, EGPEFormat fmt,
                EDDGPEPixelFormat pf, unsigned long offset, SurfaceHeap* node)
        : DDGPESurf(w, h, pBits, stride, fmt, pf), m_node(node) {
        m_fInVideoMemory       = 1;
        m_nOffsetInVideoMemory = offset;
    }
    virtual ~CerfVidSurf() {
        if (m_node) { m_node->Free(); m_node = NULL; }
    }
private:
    SurfaceHeap* m_node;
};

class CerfSysVidSurf : public DDGPESurf {
public:
    CerfSysVidSurf(int w, int h, EGPEFormat fmt) : DDGPESurf(w, h, fmt) {
        m_fInVideoMemory = 1;
    }
};

bool CerfDDGPE::EnsureVideoHeap() {
    if (m_pVidHeap) return true;
    ULONG primary = g_FbPrimaryReserve ? g_FbPrimaryReserve
                                       : g_FbStride * g_FbHeight;
    if (g_FbMemTotal <= primary) {
        CERF_LOG_X("cerf_guest: EnsureVideoHeap no offscreen; memtotal", g_FbMemTotal);
        return false;
    }
    BYTE* region = (BYTE*)((m_vidBacking == kCerfVidHeapMapped) ? CerfMapFbGlobal()
                                                                : CerfMapFbMemory());
    if (!region) {
        CERF_LOG("cerf_guest: EnsureVideoHeap FB map FAILED");
        return false;
    }
    m_fbRegionVa = region;
    m_vidSize    = g_FbMemTotal - primary;
    m_vidBaseVa  = region + primary;
    m_pVidHeap   = new SurfaceHeap(m_vidSize, 0);
    return m_pVidHeap != NULL;
}

void CerfDDGPE::GetVideoRegion(unsigned long* base, unsigned long* size) {
    EnsureVideoHeap();
    if (base) *base = (unsigned long)(ULONG_PTR)m_fbRegionVa;
    if (size) *size = g_FbMemTotal;
}

void CerfDDGPE::GetVirtualVideoMemory(unsigned long* base, unsigned long* size,
                                      unsigned long* freeBytes) {
    EnsureVideoHeap();
    if (base)      *base      = (unsigned long)m_vidBaseVa;
    if (size)      *size      = m_vidSize;
    if (freeBytes) *freeBytes = m_pVidHeap ? m_pVidHeap->Available() : 0;
}

bool CerfDDGPE::SurfaceFbPa(GPESurf* s, ULONG* pa) {
    if (s == NULL) return false;
    if (s == m_pPrimarySurface) { *pa = CerfGpeFbMemBasePa(); return true; }

    if (s->InVideoMemory() && m_vidBaseVa) {
        BYTE* buf = (BYTE*)s->Buffer();
        if (buf >= m_vidBaseVa && buf < m_vidBaseVa + m_vidSize) {
            *pa = CerfGpeFbMemBasePa() + (ULONG)(buf - m_fbRegionVa);
            return true;
        }
    }
    return false;
}

SCODE CerfDDGPE::AllocSurface(GPESurf** ppSurf, int width, int height,
                              EGPEFormat format, int surfaceFlags) {
    const bool wantVideo =
        (surfaceFlags & (GPE_REQUIRE_VIDEO_MEMORY |
                         GPE_PREFER_VIDEO_MEMORY)) != 0;
    const bool requireVideo =
        (surfaceFlags & GPE_REQUIRE_VIDEO_MEMORY) != 0;

    if (wantVideo && EnsureVideoHeap()) {
        const int bpp = CerfFormatBpp(format);
        const int stride = ((bpp * width + 31) >> 5) << 2;
        const DWORD bytes = (DWORD)stride * (DWORD)height;
        SurfaceHeap* node = m_pVidHeap->Alloc(bytes);
        if (node) {
            void* pBits = (BYTE*)m_vidBaseVa + node->Address();
            CerfVidSurf* s = new CerfVidSurf(width, height, pBits, stride,
                                             format, CerfFormatToDDGPE(format),
                                             node->Address(), node);
            if (s && s->Buffer()) {
                *ppSurf = s;
                return S_OK;
            }
            if (s) delete s; else node->Free();
        }
        if (requireVideo) { *ppSurf = NULL; return E_OUTOFMEMORY; }
    } else if (requireVideo) {
        *ppSurf = NULL;
        return E_OUTOFMEMORY;
    }

    if (surfaceFlags & GPE_BACK_BUFFER) {
        CerfSysVidSurf* bb = new CerfSysVidSurf(width, height, format);
        if (bb == NULL || bb->Buffer() == NULL) {
            if (bb) delete bb;
            *ppSurf = NULL;
            return E_OUTOFMEMORY;
        }
        *ppSurf = bb;
        return S_OK;
    }

    DDGPESurf* sys = new DDGPESurf(width, height, format);
    if (sys == NULL || sys->Buffer() == NULL) {
        if (sys) delete sys;
        *ppSurf = NULL;
        return E_OUTOFMEMORY;
    }
    *ppSurf = sys;
    return S_OK;
}

SCODE CerfDDGPE::ApplyFbMode() {
    void* fb = CerfMapFbMemory();
    if (!fb) {
        CERF_LOG("cerf_guest: GPE::ApplyFbMode FB map FAILED");
        return E_FAIL;
    }
    EGPEFormat fmt = (g_FbBpp == 16) ? gpe16Bpp
                   : (g_FbBpp == 24) ? gpe24Bpp
                   : (g_FbBpp == 32) ? gpe32Bpp : gpe8Bpp;

    if (m_pPrimarySurface) {
        delete m_pPrimarySurface;
        m_pPrimarySurface = NULL;
    }
    m_pPrimarySurface = new CerfVidSurf((int)g_FbWidth, (int)g_FbHeight, fb,
                                        (int)g_FbStride, fmt, CerfFormatToDDGPE(fmt),
                                        0u, NULL);
    if (m_pPrimarySurface == NULL) return E_OUTOFMEMORY;
    m_pPrimarySurface->SetRotation((int)g_FbWidth, (int)g_FbHeight, DMDO_0);

    m_gpeMode.width     = (int)g_FbWidth;
    m_gpeMode.height    = (int)g_FbHeight;
    m_gpeMode.Bpp       = (int)g_FbBpp;
    m_gpeMode.frequency = (int)g_FbRefreshRate;
    m_gpeMode.format    = fmt;
    m_pMode = &m_gpeMode;
    m_nScreenWidth  = m_gpeMode.width;
    m_nScreenHeight = m_gpeMode.height;
    return S_OK;
}

SCODE CerfDDGPE::SetMode(int modeId, HPALETTE* pPalette) {
    if (modeId != 0) return E_FAIL;
    CERF_LOG("cerf_guest: GPE::SetMode allocating primary");
    SCODE sc = ApplyFbMode();
    if (sc != S_OK) return sc;
    m_gpeMode.modeId = 0;

    if (pPalette) {
        if (g_FbBpp <= 8) {

            static const ULONG kLv[6] = { 0u, 51u, 102u, 153u, 204u, 255u };
            ULONG palHost[256], palRealize[256];
            palHost[0] = 0u;             palRealize[0] = 0u;
            palHost[255] = 0x00FFFFFFu;  palRealize[255] = 0x00FFFFFFu;
            int k = 1;
            for (int r = 0; r < 6; ++r)
                for (int g = 0; g < 6; ++g)
                    for (int b = 0; b < 6; ++b) {
                        ULONG R = kLv[r], G = kLv[g], B = kLv[b];
                        if ((R == 0u && G == 0u && B == 0u) ||
                            (R == 255u && G == 255u && B == 255u)) continue;
                        palHost[k]    = (R << 16) | (G << 8) | B;
                        palRealize[k] = (B << 16) | (G << 8) | R;
                        ++k;
                    }
            for (int i = 215; i < 255; ++i) {
                ULONG y = 6u + (ULONG)((i - 215) * 243 / 39);
                palHost[i] = palRealize[i] = (y << 16) | (y << 8) | y;
            }
            for (int p = 0; p < 256; ++p) {
                m_palette[p].peRed   = (BYTE)((palHost[p] >> 16) & 0xFFu);
                m_palette[p].peGreen = (BYTE)((palHost[p] >> 8) & 0xFFu);
                m_palette[p].peBlue  = (BYTE)(palHost[p] & 0xFFu);
                m_palette[p].peFlags = 0;
            }
            m_paletteEntries = 256;
            *pPalette = EngCreatePalette(PAL_INDEXED, 256, palRealize, 0, 0, 0);
            CerfPublishPalette(palHost, 0, 256);
        } else if (g_FbBpp == 16) {
            *pPalette = EngCreatePalette(PAL_BITFIELDS, 0, NULL,
                                          0xF800u, 0x07E0u, 0x001Fu);
        } else if (g_FbBpp == 32 || g_FbBpp == 24) {
            *pPalette = EngCreatePalette(PAL_BITFIELDS, 0, NULL,
                                          0x00FF0000u, 0x0000FF00u, 0x000000FFu);
        } else {
            *pPalette = EngCreatePalette(PAL_RGB, 0, NULL, 0, 0, 0);
        }
        if (*pPalette == NULL) return E_OUTOFMEMORY;
    }
    return S_OK;
}

extern "C" unsigned long CerfDDGPESurfBufferVa(unsigned long surf) {
    return surf ? (unsigned long)(ULONG_PTR)((DDGPESurf*)(ULONG_PTR)surf)->Buffer() : 0;
}

extern "C" void CerfGetVideoMem(unsigned long* base, unsigned long* size,
                                unsigned long* freeBytes) {
    ((CerfDDGPE*)GetGPE())->GetVirtualVideoMemory(base, size, freeBytes);
}

extern "C" void CerfGetVideoRegion(unsigned long* base, unsigned long* size) {
    ((CerfDDGPE*)GetGPE())->GetVideoRegion(base, size);
}

extern "C" void CerfSetVidBackingByOsMajor(unsigned long os_major) {
    ((CerfDDGPE*)GetGPE())->SetVidBacking(
        (os_major >= 6u) ? kCerfVidHeapMapped : kCerfVidHeapByPa);
}

extern "C" void CerfFillSurfaceFromSurfobj(CerfVirt::CerfBltSurface* s,
                                           SURFOBJ* pso, int y0, int y1,
                                           CerfStageWb* wb) {
    ((CerfDDGPE*)GetGPE())->FillSurfaceFromSurfobj(s, pso, y0, y1, wb);
}

extern "C" BOOL CerfDDSurfFbInfo(void* lcl, ULONG* pa, int* stride, int* bpp,
                                 int* height) {
    if (!lcl) return FALSE;
    DDGPESurf* s = DDGPESurf::GetDDGPESurf((LPDDRAWI_DDRAWSURFACE_LCL)lcl);
    if (!s) return FALSE;
    ULONG p;
    if (!((CerfDDGPE*)GetGPE())->SurfaceFbPa(s, &p)) return FALSE;
    if (pa)     *pa = p;
    if (stride) *stride = s->Stride();
    if (bpp)    *bpp = CerfFormatBpp(s->Format());
    if (height) *height = s->Height();
    return TRUE;
}
