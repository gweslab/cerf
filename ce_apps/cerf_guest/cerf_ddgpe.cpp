#include <windows.h>
#include <pkfuncs.h>
#include <winddi.h>
#include <ddgpe.h>
#include "cerf/peripherals/cerf_virt/cerf_virt_blt_descriptor.h"

extern void* CerfMapFbMemory(void);
extern "C" ULONG CerfGpeFbMemBasePa(void);
extern "C" ULONG CerfGpeBlt(ULONG desc_va);

/* RGB formats the host blitter reads/writes directly: 16/24/32bpp. */
static bool CerfConvertibleFmt(EGPEFormat f) {
    return f == gpe16Bpp || f == gpe24Bpp || f == gpe32Bpp;
}
extern ULONG g_FbWidth, g_FbHeight, g_FbBpp, g_FbStride, g_FbMemTotal;

extern "C" int APIENTRY MulDiv(int a, int b, int c) {
    if (c == 0) return -1;
    __int64 prod = (__int64)a * (__int64)b;
    if (c < 0) { prod = -prod; c = -c; }
    prod += (prod >= 0) ? (c / 2) : -(c / 2);
    return (int)(prod / c);
}

static ULONG s_CerfRgbMasks_32bpp[3] = { 0x00FF0000u, 0x0000FF00u, 0x000000FFu };
static ULONG s_CerfRgbMasks_16bpp[3] = { 0xF800u,     0x07E0u,     0x001Fu     };

static int CerfFormatBpp(EGPEFormat fmt) {
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

static EDDGPEPixelFormat CerfFormatToDDGPE(EGPEFormat fmt) {
    switch (fmt) {
        case gpe8Bpp:  return ddgpePixelFormat_8bpp;
        case gpe16Bpp: return ddgpePixelFormat_565;
        case gpe24Bpp: return ddgpePixelFormat_8880;
        case gpe32Bpp: return ddgpePixelFormat_8888;
        default:       return ddgpePixelFormat_8888;
    }
}

/* The generic DDGPESurf ctors never set m_fInVideoMemory; without setting it
   here, DDGPECreateSurface (ddhsurf.cpp:321) tags the surface SYSTEMMEMORY and
   the host HW-accel blit path never engages. */
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

class CerfDDGPE : public DDGPE {
public:
    CerfDDGPE() : DDGPE() {
        m_paletteEntries = 0;
        memset(m_palette, 0, sizeof(m_palette));
        memset(&m_gpeMode, 0, sizeof(m_gpeMode));
        m_pVidHeap  = NULL;
        m_vidBaseVa = NULL;
        m_vidBasePa = 0;
        m_vidSize   = 0;
    }

    /* Bring up the offscreen video-memory heap over the CERF fb region tail past
       the primary. Uses only the fb-reg dims (present from DLL attach), so it is
       callable at HALInit time, before SetMode allocates the primary. */
    bool EnsureVideoHeap() {
        if (m_pVidHeap) return true;
        void* base = CerfMapFbMemory();
        if (!base) {
            CERF_LOG("cerf_guest: EnsureVideoHeap FB map FAILED");
            return false;
        }
        ULONG primary = g_FbStride * g_FbHeight;
        if (g_FbMemTotal <= primary) {
            CERF_LOG_X("cerf_guest: EnsureVideoHeap no offscreen; memtotal", g_FbMemTotal);
            return false;
        }
        m_vidBaseVa = (BYTE*)base + primary;
        m_vidBasePa = CerfGpeFbMemBasePa() + primary;
        m_vidSize   = g_FbMemTotal - primary;
        m_pVidHeap  = new SurfaceHeap(m_vidSize, 0);
        CERF_LOG_X("cerf_guest: EnsureVideoHeap vidBasePa", m_vidBasePa);
        CERF_LOG_X("cerf_guest: EnsureVideoHeap vidSize",   m_vidSize);
        return m_pVidHeap != NULL;
    }

    void GetVirtualVideoMemory(unsigned long* base, unsigned long* size,
                               unsigned long* freeBytes) {
        EnsureVideoHeap();
        if (base)      *base      = (unsigned long)m_vidBaseVa;
        if (size)      *size      = m_vidSize;
        if (freeBytes) *freeBytes = m_pVidHeap ? m_pVidHeap->Available() : 0;
        CERF_LOG_X("cerf_guest: GetVirtualVideoMemory size", m_vidSize);
    }

    bool SurfaceFbPa(GPESurf* s, ULONG* pa) {
        if (s == NULL) return false;
        if (s == m_pPrimarySurface) { *pa = CerfGpeFbMemBasePa(); return true; }
        if (s->InVideoMemory()) {
            *pa = m_vidBasePa + s->OffsetInVideoMemory();
            return true;
        }
        return false;
    }

    virtual SCODE BltPrepare(GPEBltParms* p) {
        /* The host blitter handles any rop / stretch / transparent / mask /
           brush / alpha to a 16/24/32bpp addressable dst; HwBlt validates the
           src/mask/brush and falls back to the GPE software blit otherwise. */
        ULONG pa;
        if (p->pDst && p->prclDst && CerfConvertibleFmt(p->pDst->Format()) &&
            (SurfaceFbPa(p->pDst, &pa) || p->pDst->Buffer() != NULL)) {
            p->pBlt = (SCODE (GPE::*)(GPEBltParms*))&CerfDDGPE::HwBlt;
            return S_OK;
        }
        p->pBlt = &GPE::EmulatedBlt;
        return S_OK;
    }

    static void RectToDesc(CerfVirt::CerfBltRect* r, const RECTL* s) {
        r->left = s->left; r->top = s->top; r->right = s->right; r->bottom = s->bottom;
    }

    void FillSurface(CerfVirt::CerfBltSurface* s, GPESurf* surf) {
        ULONG pa;
        s->format = (uint32_t)surf->Format();
        s->stride = (int32_t)surf->Stride();
        if (SurfaceFbPa(surf, &pa)) { s->buffer = pa; s->is_fb_pa = 1u; }
        else { s->buffer = (uint32_t)(ULONG_PTR)surf->Buffer(); s->is_fb_pa = 0u; }
        GPEFormat* gf = surf->FormatPtr();
        s->pal_entries = gf ? (uint32_t)gf->m_PaletteEntries : 0u;
        if (gf && gf->m_pPalette && (gf->m_PaletteEntries == 3 || gf->m_PaletteEntries == 4)) {
            for (int i = 0; i < gf->m_PaletteEntries; ++i) s->mask[i] = gf->m_pPalette[i];
        }
        if (surf->IsRotate()) {
            s->is_rotate = 1u;
            switch (surf->Rotate()) {
                case DMDO_90:  s->rotate = CerfVirt::kCerfRotate90;  break;
                case DMDO_180: s->rotate = CerfVirt::kCerfRotate180; break;
                case DMDO_270: s->rotate = CerfVirt::kCerfRotate270; break;
                default:       s->rotate = CerfVirt::kCerfRotate0;   break;
            }
            s->screen_w = (uint32_t)surf->ScreenWidth();
            s->screen_h = (uint32_t)surf->ScreenHeight();
        }
    }

    /* Resolve a SURFOBJ to a host surface the same way the GPE lib does
       (TmpGPESurf): a device-managed surface carries its GPESurf in dhsurf;
       an engine bitmap exposes its bits directly. Used by DrvGradientFill,
       which receives a raw SURFOBJ rather than a GPESurf. */
    void FillSurfaceFromSurfobj(CerfVirt::CerfBltSurface* s, SURFOBJ* pso) {
        if (!pso) return;
        if (pso->dhsurf) { FillSurface(s, (GPESurf*)pso->dhsurf); return; }
        /* gpe.h IFormatToEGPEFormat[] maps BMF_16/24/32 (4/5/6) to gpe16/24/32Bpp
           (4/5/6) — identity for the formats the host renders; lower BMF values
           differ but the host declines them (ResolveMasks fails). */
        s->format   = (uint32_t)pso->iBitmapFormat;
        s->stride   = (int32_t)pso->lDelta;
        s->buffer   = (uint32_t)(ULONG_PTR)pso->pvScan0;
        s->is_fb_pa = 0u;
    }

    /* SW fallback when the host engine cannot handle a blit (non-convertible dst,
       palettized src without lookup, untranslatable page). */
    SCODE SwFallback(GPEBltParms* p) { return GPE::EmulatedBlt(p); }

    /* Build a full blit descriptor from GPEBltParms and run it on the host. The
       host covers every rop / stretch / mask / brush / alpha case; on an
       untranslatable page or a format it does not handle it returns non-done
       and we fall back to the GPE software blit. */
    SCODE HwBlt(GPEBltParms* p) {
        if (!p->pDst || !p->prclDst || !CerfConvertibleFmt(p->pDst->Format()))
            return SwFallback(p);
        ULONG pa;
        if (!SurfaceFbPa(p->pDst, &pa) && !p->pDst->Buffer()) return SwFallback(p);

        CerfVirt::CerfBltDescriptor d;
        memset(&d, 0, sizeof(d));
        d.magic          = CerfVirt::kCerfBltMagic;
        d.rop4           = (uint32_t)p->rop4;
        d.blt_flags      = (uint32_t)p->bltFlags;
        d.solid_color    = (uint32_t)p->solidColor;
        d.i_mode         = (uint32_t)p->iMode;
        d.x_positive     = p->xPositive ? 1u : 0u;
        d.y_positive     = p->yPositive ? 1u : 0u;
        d.blend_function = *(const ULONG*)&p->blendFunction;
        RectToDesc(&d.dst_rect, p->prclDst);
        FillSurface(&d.dst, p->pDst);

        if (p->pSrc && p->prclSrc) {
            const bool pal = CerfFormatBpp(p->pSrc->Format()) <= 8;  /* palettized index */
            if (pal) { if (!p->pLookup) return SwFallback(p); }
            else if (!CerfConvertibleFmt(p->pSrc->Format())) return SwFallback(p);
            if (!SurfaceFbPa(p->pSrc, &pa) && !p->pSrc->Buffer()) return SwFallback(p);
            d.has_src        = 1u;
            d.convert_active = (!pal && p->pConvert != NULL) ? 1u : 0u;
            d.lookup_va      = pal ? (uint32_t)(ULONG_PTR)p->pLookup : 0u;
            RectToDesc(&d.src_rect, p->prclSrc);
            FillSurface(&d.src, p->pSrc);
        }
        if (p->pMask && p->prclMask && p->pMask->Buffer()) {
            d.has_mask = 1u;
            RectToDesc(&d.mask_rect, p->prclMask);
            FillSurface(&d.mask, p->pMask);
        }
        if (p->pBrush) {
            d.has_brush    = 1u;
            d.brush_width  = (uint32_t)p->pBrush->Width();
            d.brush_height = (uint32_t)p->pBrush->Height();
            FillSurface(&d.brush, p->pBrush);
            if (p->pptlBrush) {
                d.brush_has_ptl = 1u;
                d.brush_ptl_x   = p->pptlBrush->x;
                d.brush_ptl_y   = p->pptlBrush->y;
            }
        }
        if (p->prclClip) {
            d.has_clip = 1u;
            RectToDesc(&d.clip_rect, p->prclClip);
        }

        const ULONG cgb = CerfGpeBlt((ULONG)(ULONG_PTR)&d);
        return (cgb == 2u) ? S_OK : SwFallback(p);
    }

    virtual SCODE BltComplete(GPEBltParms* p) {
        CERF_LOG_X("cerf_guest: GPE::BltComplete rop4", p ? p->rop4 : 0);
        return S_OK;
    }

    virtual SCODE Line(GPELineParms* pLineParms, EGPEPhase phase) {
        CERF_LOG_X("cerf_guest: GPE::Line phase", phase);
        if (phase == gpeSingle || phase == gpePrepare) {
            pLineParms->pLine = &GPE::EmulatedLine;
        }
        return S_OK;
    }

    /* The DDGPE lib's AllocVideoSurface routes here with GPE_REQUIRE_VIDEO_MEMORY
       (ddgpe.cpp:85 -> AllocSurface(DDGPESurf**) -> (GPESurf**) cast, which drops
       pixelFormat — re-derived from format). REQUIRE/BACK_BUFFER must come from
       video memory; PREFER tries video then falls back; otherwise system memory. */
    virtual SCODE AllocSurface(GPESurf** ppSurf, int width, int height,
                               EGPEFormat format, int surfaceFlags) {
        CERF_LOG_X("cerf_guest: AllocSurface w", (DWORD)width);
        CERF_LOG_X("cerf_guest: AllocSurface h", (DWORD)height);
        CERF_LOG_X("cerf_guest: AllocSurface fmt", (DWORD)format);
        CERF_LOG_X("cerf_guest: AllocSurface flags", (DWORD)surfaceFlags);

        const bool wantVideo =
            (surfaceFlags & (GPE_REQUIRE_VIDEO_MEMORY |
                             GPE_PREFER_VIDEO_MEMORY |
                             GPE_BACK_BUFFER)) != 0;
        const bool requireVideo =
            (surfaceFlags & (GPE_REQUIRE_VIDEO_MEMORY | GPE_BACK_BUFFER)) != 0;

        if (wantVideo && EnsureVideoHeap()) {
            const int bpp = CerfFormatBpp(format);
            const int stride = ((bpp * width + 31) >> 5) << 2;  /* ddgpesurf.cpp:66 */
            const DWORD bytes = (DWORD)stride * (DWORD)height;
            SurfaceHeap* node = m_pVidHeap->Alloc(bytes);
            if (node) {
                void* pBits = (BYTE*)m_vidBaseVa + node->Address();
                CerfVidSurf* s = new CerfVidSurf(width, height, pBits, stride,
                                                 format, CerfFormatToDDGPE(format),
                                                 node->Address(), node);
                if (s && s->Buffer()) {
                    CERF_LOG_X("cerf_guest: AllocSurface video offset", node->Address());
                    CERF_LOG_X("cerf_guest: AllocSurface video obj", (DWORD)(ULONG_PTR)s);
                    *ppSurf = s;
                    return S_OK;
                }
                if (s) delete s; else node->Free();
            }
            CERF_LOG("cerf_guest: AllocSurface video carve failed");
            if (requireVideo) { *ppSurf = NULL; return E_OUTOFMEMORY; }
        } else if (requireVideo) {
            CERF_LOG("cerf_guest: AllocSurface require-video but no heap");
            *ppSurf = NULL;
            return E_OUTOFMEMORY;
        }

        GPESurf* sys = new GPESurf(width, height, format);
        if (sys == NULL || sys->Buffer() == NULL) {
            if (sys) delete sys;
            *ppSurf = NULL;
            return E_OUTOFMEMORY;
        }
        CERF_LOG("cerf_guest: AllocSurface system memory");
        *ppSurf = sys;
        return S_OK;
    }

    virtual SCODE SetPointerShape(GPESurf*, GPESurf*, int, int, int, int) {
        CERF_LOG("cerf_guest: GPE::SetPointerShape");
        return 1; /* SPS_DECLINE — engine handles SW cursor via DrvBitBlt */
    }

    virtual SCODE MovePointer(int, int) {
        CERF_LOG("cerf_guest: GPE::MovePointer");
        return S_OK;
    }

    virtual SCODE SetPalette(const PALETTEENTRY* src, unsigned short firstEntry,
                             unsigned short numEntries) {
        CERF_LOG_X("cerf_guest: GPE::SetPalette numEntries", (DWORD)numEntries);
        if (src && firstEntry + numEntries <= 256) {
            for (unsigned short i = 0; i < numEntries; ++i) {
                m_palette[firstEntry + i] = src[i];
            }
            if (firstEntry + numEntries > m_paletteEntries) {
                m_paletteEntries = firstEntry + numEntries;
            }
        }
        return S_OK;
    }

    virtual SCODE GetPalette(PALETTEENTRY** ppPalette, unsigned short* pcEntries) {
        CERF_LOG_X("cerf_guest: GPE::GetPalette entries", (DWORD)m_paletteEntries);
        if (ppPalette) *ppPalette = (m_paletteEntries > 0) ? m_palette : NULL;
        if (pcEntries) *pcEntries = m_paletteEntries;
        return S_OK;
    }

    virtual SCODE GetModeInfo(GPEMode* pMode, int modeNo) {
        CERF_LOG_X("cerf_guest: GPE::GetModeInfo modeNo", (DWORD)modeNo);
        if (modeNo != 0 || pMode == NULL) return E_FAIL;
        pMode->modeId    = 0;
        pMode->width     = (int)g_FbWidth;
        pMode->height    = (int)g_FbHeight;
        pMode->Bpp       = (int)g_FbBpp;
        pMode->frequency = 60;
        pMode->format    = (g_FbBpp == 16) ? gpe16Bpp
                         : (g_FbBpp == 24) ? gpe24Bpp
                         : (g_FbBpp == 32) ? gpe32Bpp : gpe8Bpp;
        return S_OK;
    }

    virtual int NumModes() {
        CERF_LOG("cerf_guest: GPE::NumModes");
        return 1;
    }

    virtual SCODE SetMode(int modeId, HPALETTE* pPalette) {
        /* HFLAT/flat.cpp:263-409 — sets m_pMode, m_pPrimarySurface, m_nScreen{Width,Height},
           and CRITICALLY assigns *pPalette via EngCreatePalette for the caller. */
        if (modeId != 0) return E_FAIL;
        CERF_LOG("cerf_guest: GPE::SetMode allocating primary");
        void* fb = CerfMapFbMemory();
        if (!fb) {
            CERF_LOG("cerf_guest: GPE::SetMode FB map FAILED");
            return E_FAIL;
        }
        EGPEFormat fmt = (g_FbBpp == 16) ? gpe16Bpp
                       : (g_FbBpp == 24) ? gpe24Bpp
                       : (g_FbBpp == 32) ? gpe32Bpp : gpe8Bpp;

        if (m_pPrimarySurface) {
            delete m_pPrimarySurface;
            m_pPrimarySurface = NULL;
        }
        /* Primary MUST be a DDGPESurf, not a plain GPESurf: DDGPECreateSurface calls
           the DDGPESurf virtual SetDDGPESurf() on the primary for a
           DDSCAPS_PRIMARYSURFACE request (ddhsurf.cpp:204); a plain GPESurf has no
           such vtable and the virtual call faults. */
        m_pPrimarySurface = new DDGPESurf((int)g_FbWidth, (int)g_FbHeight, fb,
                                          (int)g_FbStride, fmt, CerfFormatToDDGPE(fmt));
        if (m_pPrimarySurface == NULL) return E_OUTOFMEMORY;

        m_gpeMode.modeId    = modeId;
        m_gpeMode.width     = (int)g_FbWidth;
        m_gpeMode.height    = (int)g_FbHeight;
        m_gpeMode.Bpp       = (int)g_FbBpp;
        m_gpeMode.frequency = 60;
        m_gpeMode.format    = fmt;
        m_pMode = &m_gpeMode;
        m_nScreenWidth  = m_gpeMode.width;
        m_nScreenHeight = m_gpeMode.height;

        if (pPalette) {
            if (g_FbBpp == 16) {
                *pPalette = EngCreatePalette(PAL_BITFIELDS, 0, NULL,
                                              0xF800u, 0x07E0u, 0x001Fu);
            } else if (g_FbBpp == 32 || g_FbBpp == 24) {
                *pPalette = EngCreatePalette(PAL_BITFIELDS, 0, NULL,
                                              0x00FF0000u, 0x0000FF00u, 0x000000FFu);
            } else {
                *pPalette = EngCreatePalette(PAL_RGB, 0, NULL, 0, 0, 0);
            }
            CERF_LOG_X("cerf_guest: GPE::SetMode palette handle", (DWORD)*pPalette);
            if (*pPalette == NULL) return E_OUTOFMEMORY;
        }

        CERF_LOG_X("cerf_guest: GPE::SetMode primary surface", (DWORD)m_pPrimarySurface);
        return S_OK;
    }

    virtual int InVBlank() {
        CERF_LOG("cerf_guest: GPE::InVBlank");
        return 0;
    }

    virtual ULONG GetGraphicsCaps() {
        CERF_LOG("cerf_guest: GPE::GetGraphicsCaps");
        return 0;
    }

    virtual ULONG DrvEscape(SURFOBJ* pso, ULONG iEsc, ULONG cjIn, PVOID pvIn,
                            ULONG cjOut, PVOID pvOut) {
        DWORD firstIn = (pvIn && cjIn >= sizeof(ULONG)) ? *(DWORD*)pvIn : 0xFFFFFFFFu;
        ULONG r = GPE::DrvEscape(pso, iEsc, cjIn, pvIn, cjOut, pvOut);
        CERF_LOG_X("cerf_guest: DrvEscape iEsc", (DWORD)iEsc);
        CERF_LOG_X("cerf_guest: DrvEscape firstIn", firstIn);
        CERF_LOG_X("cerf_guest: DrvEscape ret", (DWORD)r);
        return r;
    }

    virtual BOOL  IsPaletteSettable() {
        CERF_LOG("cerf_guest: GPE::IsPaletteSettable");
        return (g_FbBpp <= 8);
    }

    virtual BOOL GetScreenDimensions(GPEScreenProps* pProps) {
        CERF_LOG("cerf_guest: GPE::GetScreenDimensions");
        if (!pProps) return FALSE;
        pProps->ulHorzSize   = (g_FbWidth  * 254) / 96 / 10;
        pProps->ulVertSize   = (g_FbHeight * 254) / 96 / 10;
        pProps->ulLogPixelsX = 96;
        pProps->ulLogPixelsY = 96;
        pProps->ulAspectX    = 36;
        pProps->ulAspectY    = 36;
        pProps->ulAspectXY   = 51;
        return TRUE;
    }

    virtual ULONG* GetClearTypeRGBMasks() {
        CERF_LOG("cerf_guest: GPE::GetClearTypeRGBMasks");
        return (g_FbBpp == 16) ? s_CerfRgbMasks_16bpp
             : (g_FbBpp == 32) ? s_CerfRgbMasks_32bpp : NULL;
    }

private:
    GPEMode         m_gpeMode;
    unsigned short  m_paletteEntries;
    PALETTEENTRY    m_palette[256];
    SurfaceHeap*    m_pVidHeap;
    BYTE*           m_vidBaseVa;
    ULONG           m_vidBasePa;
    ULONG           m_vidSize;
};

extern "C" GPE* GetGPE() {
    static CerfDDGPE* s_instance = NULL;
    if (!s_instance) s_instance = new CerfDDGPE();
    return s_instance;
}

/* GetVirtualVideoMemory is CerfDDGPE-specific (not a GPE base virtual), so the
   DD-HAL in a separate TU reaches the offscreen extent through this shim. */
extern "C" void CerfGetVideoMem(unsigned long* base, unsigned long* size,
                                unsigned long* freeBytes) {
    ((CerfDDGPE*)GetGPE())->GetVirtualVideoMemory(base, size, freeBytes);
}

/* The SURFOBJ->surface resolution (FB-PA + masks) is CerfDDGPE-instance state,
   so a DDI function in a separate TU reaches it through this shim. */
extern "C" void CerfFillSurfaceFromSurfobj(CerfVirt::CerfBltSurface* s,
                                           SURFOBJ* pso) {
    ((CerfDDGPE*)GetGPE())->FillSurfaceFromSurfobj(s, pso);
}
