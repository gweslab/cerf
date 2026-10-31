#include "cerf_ddgpe_ddhal.h"
#include "cerf_ddgpe.h"
#include "cerf_ddgpe_primary_layout.h"
#include "include/ddraw_ce6.h"

static bool CerfDDrawDetectFmt(const Ce6_DDSURFACEDESC* d, EGPEFormat* fmt,
                               EDDGPEPixelFormat* pf) {
    DWORD bpp = d ? d->ddpfPixelFormat.dwRGBBitCount : 0u;
    switch (bpp) {
        case 8:  *fmt = gpe8Bpp;  *pf = ddgpePixelFormat_8bpp; return true;
        case 16: *fmt = gpe16Bpp; *pf = ddgpePixelFormat_565;  return true;
        case 24: *fmt = gpe24Bpp; *pf = ddgpePixelFormat_8880; return true;
        case 32: *fmt = gpe32Bpp; *pf = ddgpePixelFormat_8888; return true;
    }
    return false;
}

extern "C" DWORD WINAPI DDGPECanCreateSurface(Ce6_DDHAL_CANCREATESURFACEDATA* pd) {
    pd->ddRVal = CERF_DD_OK;
    if (pd->bIsDifferentPixelFormat) {
        EGPEFormat fmt; EDDGPEPixelFormat pf;
        if (!CerfDDrawDetectFmt(pd->lpDDSurfaceDesc, &fmt, &pf))
            pd->ddRVal = CERF_DDERR_UNSUPPORTEDFORMAT;
    }
    return DDHAL_DRIVER_HANDLED;
}

extern "C" DWORD WINAPI DDGPECreateSurface(Ce6_DDHAL_CREATESURFACEDATA* pd) {
    Ce6_DDSURFACEDESC* desc = pd->lpDDSurfaceDesc;
    CerfDDGPE* gpe = (CerfDDGPE*)GetGPE();
    DDGPESurf* primary = gpe->DDGPEPrimarySurface();

    unsigned int nWidth  = desc ? desc->dwWidth  : 0u;
    unsigned int nHeight = desc ? desc->dwHeight : 0u;
    DWORD        dwFlags = desc ? desc->dwFlags  : 0u;

    EGPEFormat fmt = primary ? primary->Format() : gpe16Bpp;
    EDDGPEPixelFormat pf = CerfFormatToDDGPE(fmt);
    if (desc && desc->ddpfPixelFormat.dwRGBBitCount)
        CerfDDrawDetectFmt(desc, &fmt, &pf);

    int aw = (int)nWidth;
    int ah = (int)nHeight;
    if ((aw <= 0 || ah <= 0) && primary) { aw = primary->Width(); ah = primary->Height(); }

    BOOL bPrimaryChain = FALSE;
    for (DWORD i = 0; i < pd->dwSCnt; ++i) {
        Ce6_DDRAWSURFACE_LCL* lcl = pd->lplpSList[i];
        DWORD dwCaps = lcl->ddsCaps.dwCaps;
        if (i == 0) bPrimaryChain = (dwCaps & CE6_DDSCAPS_PRIMARYSURFACE) != 0u;

        SCODE sc = S_OK;
        if (bPrimaryChain && (dwCaps & CE6_DDSCAPS_PRIMARYSURFACE)) {
            if (!primary) { pd->ddRVal = CERF_DDERR_GENERIC; return DDHAL_DRIVER_HANDLED; }
            primary->SetDDGPESurf(lcl);
        } else {
            GPESurf*   s              = NULL;
            const bool display_memory = bPrimaryChain || (dwCaps & CE6_DDSCAPS_VIDEOMEMORY) != 0u;
            if (bPrimaryChain) {
                sc = gpe->AllocBackBuffer(&s);
            } else if (dwCaps & CE6_DDSCAPS_VIDEOMEMORY) {
                sc = gpe->AllocSurface(&s, aw, ah, fmt, GPE_REQUIRE_VIDEO_MEMORY);
            } else if (dwFlags & CE6_DDSD_LPSURFACE) {
                int stride = desc->lPitch ? (int)desc->lPitch
                                          : CerfEGPEFormatStride(aw, fmt);
                s = new DDGPESurf(aw, ah, desc->lpSurface, stride, fmt, pf);
                if (!s || !s->Buffer()) { if (s) delete s; s = NULL; sc = E_OUTOFMEMORY; }
            } else if (dwCaps & CE6_DDSCAPS_SYSTEMMEMORY) {
                sc = gpe->AllocSurface(&s, aw, ah, fmt, 0);
            } else {
                sc = gpe->AllocSurface(&s, aw, ah, fmt, GPE_PREFER_VIDEO_MEMORY);
            }
            if (FAILED(sc) || !s) {
                pd->ddRVal = display_memory ? CERF_DDERR_OUTOFVIDEOMEMORY : (sc ? sc : CERF_DDERR_OUTOFMEMORY);
                return DDHAL_DRIVER_HANDLED;
            }
            ((DDGPESurf*)s)->SetDDGPESurf(lcl);
        }

        DDGPESurf* bound = DDGPESurf::GetDDGPESurf(lcl);
        if (bound && bound->InVideoMemory()) lcl->ddsCaps.dwCaps |= CE6_DDSCAPS_VIDEOMEMORY;
        else                                 lcl->ddsCaps.dwCaps |= CE6_DDSCAPS_SYSTEMMEMORY;
    }

    if (bPrimaryChain) {
        CerfPrimaryLayout chain;
        CerfPrimaryLayoutFor(primary->Rotate(), primary->ScreenWidth(), primary->ScreenHeight(),
                             primary->Stride(), primary->BytesPerPixel(), &chain);
        for (DWORD i = 0; i < pd->dwSCnt; ++i) {
            if (CerfPrimaryLayoutBind(pd->lplpSList[i], &chain)) continue;
            for (DWORD j = 0; j < i; ++j) CerfPrimaryLayoutForget(pd->lplpSList[j]);
            pd->ddRVal = CERF_DDERR_OUTOFMEMORY;
            return DDHAL_DRIVER_HANDLED;
        }
    }

    if (desc && pd->dwSCnt) {
        DDGPESurf* s0 = DDGPESurf::GetDDGPESurf(pd->lplpSList[0]);
        if (s0) {
            CerfPrimaryLayout lay;
            gpe->SurfaceLayout(pd->lplpSList[0], s0, &lay);
            desc->lPitch  = lay.y_pitch;
            desc->lXPitch = lay.x_pitch;
            desc->dwSurfaceSize = (DWORD)s0->Stride() * (DWORD)s0->ScreenHeight();
            desc->dwFlags |= (CE6_DDSD_PITCH | CE6_DDSD_XPITCH | CE6_DDSD_SURFACESIZE);
            if (s0->InVideoMemory()) desc->ddsCaps.dwCaps |= CE6_DDSCAPS_VIDEOMEMORY;
            else                     desc->ddsCaps.dwCaps |= CE6_DDSCAPS_SYSTEMMEMORY;
        }
    }

    pd->ddRVal = CERF_DD_OK;
    return DDHAL_DRIVER_HANDLED;
}

extern "C" DWORD WINAPI DDGPEDestroySurface(Ce6_DDHAL_DESTROYSURFACEDATA* pd) {
    CerfDDGPE* gpe = (CerfDDGPE*)GetGPE();
    DDGPESurf* s = DDGPESurf::GetDDGPESurf(pd->lpDDSurface);
    if (s && s != (DDGPESurf*)gpe->PrimarySurface()) {
        gpe->ReleaseScanout(s);
        delete s;
        pd->lpDDSurface->dwReserved1 = 0;
    }
    CerfPrimaryLayoutForget(pd->lpDDSurface);
    pd->ddRVal = CERF_DD_OK;
    return DDHAL_DRIVER_HANDLED;
}

extern "C" DWORD WINAPI DDGPEFlip(Ce6_DDHAL_FLIPDATA* pd) {
    if (pd->lpSurfCurr->ddsCaps.dwCaps & CE6_DDSCAPS_PRIMARYSURFACE)
        ((CerfDDGPE*)GetGPE())->SetVisibleSurface(DDGPESurf::GetDDGPESurf(pd->lpSurfTarg),
                                                  (pd->dwFlags & CERF_DDFLIP_WAITVSYNC) != 0u);
    pd->ddRVal = CERF_DD_OK;
    return DDHAL_DRIVER_HANDLED;
}

extern "C" DWORD WINAPI DDGPELock(Ce6_DDHAL_LOCKDATA* pd) {
    DDGPESurf* s = DDGPESurf::GetDDGPESurf(pd->lpDDSurface);
    if (!s || !s->Buffer()) { pd->ddRVal = CERF_DDERR_INVALIDOBJECT; return DDHAL_DRIVER_HANDLED; }
    int x = pd->bHasRect ? pd->rArea.left : 0;
    int y = pd->bHasRect ? pd->rArea.top  : 0;
    ULONG addr = (ULONG)(ULONG_PTR)s->Buffer()
               + (ULONG)y * (ULONG)s->Stride()
               + (ULONG)x * (ULONG)s->BytesPerPixel();
    pd->lpSurfData = (LPVOID)(ULONG_PTR)addr;
    pd->ddRVal = CERF_DD_OK;
    return DDHAL_DRIVER_HANDLED;
}

extern "C" DWORD WINAPI DDGPEUnlock(Ce6_DDHAL_UNLOCKDATA* pd) {
    pd->ddRVal = CERF_DD_OK;
    return DDHAL_DRIVER_HANDLED;
}

extern "C" DWORD WINAPI DDGPESetColorKey(Ce6_DDHAL_SETCOLORKEYDATA* pd) {
    DDGPESurf* s = DDGPESurf::GetDDGPESurf(pd->lpDDSurface);
    if (!s) { pd->ddRVal = CERF_DDERR_INVALIDOBJECT; return DDHAL_DRIVER_HANDLED; }
    if (pd->dwFlags == CERF_DDCKEY_SRCBLT) {
        s->SetColorKey(pd->ckNew.dwColorSpaceLowValue, pd->ckNew.dwColorSpaceHighValue);
        pd->ddRVal = CERF_DD_OK;
    } else {
        pd->ddRVal = CERF_DDERR_NOCOLORKEYHW;
    }
    return DDHAL_DRIVER_HANDLED;
}

extern "C" DWORD WINAPI DDGPEGetFlipStatus(Ce6_DDHAL_GETFLIPSTATUSDATA* pd) {
    pd->ddRVal = CERF_DD_OK;
    return DDHAL_DRIVER_HANDLED;
}

extern "C" DWORD WINAPI DDGPESetPalette(Ce6_DDHAL_SETPALETTEDATA* pd) {
    pd->ddRVal = CERF_DD_OK;
    return DDHAL_DRIVER_HANDLED;
}

extern "C" DWORD WINAPI DDGPECreatePalette(Ce6_DDHAL_CREATEPALETTEDATA* pd) {
    pd->ddRVal = CERF_DD_OK;
    return DDHAL_DRIVER_HANDLED;
}

extern "C" DWORD WINAPI DDGPEWaitForVerticalBlank(Ce6_DDHAL_WAITFORVERTICALBLANKDATA* pd) {
    pd->bIsInVB = (DWORD)((CerfDDGPE*)GetGPE())->InVBlank();
    pd->ddRVal = CERF_DD_OK;
    return DDHAL_DRIVER_HANDLED;
}
