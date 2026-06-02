#include <windows.h>
#include <pkfuncs.h>
#include <winddi.h>
#include <gpe.h>

#define CERF_VIRT_DEBUG_TX_PA  0xD0000000u
#define CERF_VIRT_DEBUG_TX_SZ  0x1000u
#define CERF_VIRT_FB_REGS_PA   0xD0001000u
#define CERF_VIRT_FB_REGS_SZ   0x1000u
#define CERF_VIRT_GPE_CMD_PA   0xD0002000u
#define CERF_VIRT_GPE_CMD_SZ   0x1000u
#define CERF_VIRT_FB_MEM_PA    0xD0100000u

#define CERF_GPE_DESC_VA          0x000u
#define CERF_GPE_STATUS           0x004u
#define CERF_GPE_KICK_OFFSET      0x800u
#define CERF_GPE_GRAD_KICK_OFFSET 0x804u
#define CERF_GPE_STATUS_DONE      2u

static volatile UCHAR* s_debug_tx = NULL;
static volatile ULONG* s_fb_regs  = NULL;
static volatile ULONG* s_gpe_cmd  = NULL;
ULONG g_FbWidth   = 0;
ULONG g_FbHeight  = 0;
ULONG g_FbBpp     = 0;
ULONG g_FbStride  = 0;
ULONG g_FbMemPa   = 0;
ULONG g_FbMemTotal = 0;   /* total host-backed region bytes (kFbRegMemSizeTotal);
                             region tail past the primary = DDraw video memory. */
void* g_FbMemVa   = NULL;
ULONG g_EngineVersion = 0;

static void CerfDebugTxInit(void) {
    if (s_debug_tx) return;
    s_debug_tx = (volatile UCHAR*)VirtualAlloc(0, CERF_VIRT_DEBUG_TX_SZ,
                                                MEM_RESERVE, PAGE_NOACCESS);
    if (!s_debug_tx) return;
    if (!VirtualCopy((LPVOID)s_debug_tx,
                     (LPVOID)(CERF_VIRT_DEBUG_TX_PA >> 8),
                     CERF_VIRT_DEBUG_TX_SZ,
                     PAGE_READWRITE | PAGE_NOCACHE | PAGE_PHYSICAL)) {
        VirtualFree((LPVOID)s_debug_tx, 0, MEM_RELEASE);
        s_debug_tx = NULL;
    }
}

#if CERF_DEV_MODE
extern "C" void CerfDebugTx(const char* msg) {
    if (!s_debug_tx) CerfDebugTxInit();
    if (!s_debug_tx || !msg) return;
    for (const char* p = msg; *p; ++p) s_debug_tx[0] = (UCHAR)*p;
    s_debug_tx[0] = '\n';
}

extern "C" void CerfDebugTxX(const char* msg, DWORD value) {
    if (!s_debug_tx) CerfDebugTxInit();
    if (!s_debug_tx || !msg) return;
    for (const char* p = msg; *p; ++p) s_debug_tx[0] = (UCHAR)*p;
    s_debug_tx[0] = ' '; s_debug_tx[0] = '0'; s_debug_tx[0] = 'x';
    static const char hex[] = "0123456789ABCDEF";
    for (int i = 7; i >= 0; --i) s_debug_tx[0] = hex[(value >> (i * 4)) & 0xF];
    s_debug_tx[0] = '\n';
}
#endif

void CerfReadFbRegs(void) {
    CERF_LOG("cerf_guest: CerfReadFbRegs entry");
    if (s_fb_regs) { CERF_LOG("cerf_guest: CerfReadFbRegs cached"); return; }
    s_fb_regs = (volatile ULONG*)VirtualAlloc(0, CERF_VIRT_FB_REGS_SZ,
                                               MEM_RESERVE, PAGE_NOACCESS);
    if (!s_fb_regs) return;
    if (!VirtualCopy((LPVOID)s_fb_regs,
                     (LPVOID)(CERF_VIRT_FB_REGS_PA >> 8),
                     CERF_VIRT_FB_REGS_SZ,
                     PAGE_READWRITE | PAGE_NOCACHE | PAGE_PHYSICAL)) {
        VirtualFree((LPVOID)s_fb_regs, 0, MEM_RELEASE);
        s_fb_regs = NULL;
        return;
    }
    g_FbWidth  = s_fb_regs[0];
    g_FbHeight = s_fb_regs[1];
    g_FbBpp    = s_fb_regs[2];
    g_FbStride = s_fb_regs[3];
    g_FbMemPa   = s_fb_regs[5];   /* kFbRegMemBasePa   (0x14 >> 2) */
    g_FbMemTotal = s_fb_regs[7];  /* kFbRegMemSizeTotal (0x1C >> 2) */
    CERF_LOG_X("cerf_guest: CerfReadFbRegs w",      g_FbWidth);
    CERF_LOG_X("cerf_guest: CerfReadFbRegs h",      g_FbHeight);
    CERF_LOG_X("cerf_guest: CerfReadFbRegs bpp",    g_FbBpp);
    CERF_LOG_X("cerf_guest: CerfReadFbRegs stride", g_FbStride);
    CERF_LOG_X("cerf_guest: CerfReadFbRegs mempa",  g_FbMemPa);
    CERF_LOG_X("cerf_guest: CerfReadFbRegs memtotal", g_FbMemTotal);
}

BOOL CerfMapGpeCmd(void) {
    CERF_LOG("cerf_guest: CerfMapGpeCmd entry");
    if (s_gpe_cmd) return TRUE;
    s_gpe_cmd = (volatile ULONG*)VirtualAlloc(0, CERF_VIRT_GPE_CMD_SZ,
                                               MEM_RESERVE, PAGE_NOACCESS);
    if (!s_gpe_cmd) return FALSE;
    if (!VirtualCopy((LPVOID)s_gpe_cmd,
                     (LPVOID)(CERF_VIRT_GPE_CMD_PA >> 8),
                     CERF_VIRT_GPE_CMD_SZ,
                     PAGE_READWRITE | PAGE_NOCACHE | PAGE_PHYSICAL)) {
        VirtualFree((LPVOID)s_gpe_cmd, 0, MEM_RELEASE);
        s_gpe_cmd = NULL;
        return FALSE;
    }
    return TRUE;
}

/* Publish the guest VA of a filled CerfBltDescriptor and kick; the host reads
   it through the live MMU, runs the blit, and returns the status word. */
extern "C" ULONG CerfGpeBlt(ULONG desc_va) {
    if (!CerfMapGpeCmd()) return (ULONG)-1;
    s_gpe_cmd[CERF_GPE_DESC_VA / 4] = desc_va;
    *(volatile ULONG*)(((volatile UCHAR*)s_gpe_cmd) + CERF_GPE_KICK_OFFSET) = 1u;
    return s_gpe_cmd[CERF_GPE_STATUS / 4];
}

/* Publish a filled CerfGradDescriptor and kick the gradient port; the host
   reads it through the live MMU, paints the ramp, and returns the status. */
extern "C" ULONG CerfGpeGrad(ULONG desc_va) {
    if (!CerfMapGpeCmd()) return (ULONG)-1;
    s_gpe_cmd[CERF_GPE_DESC_VA / 4] = desc_va;
    *(volatile ULONG*)(((volatile UCHAR*)s_gpe_cmd) + CERF_GPE_GRAD_KICK_OFFSET) = 1u;
    return s_gpe_cmd[CERF_GPE_STATUS / 4];
}

extern "C" ULONG CerfGpeFbMemBasePa(void) { return CERF_VIRT_FB_MEM_PA; }

void* CerfMapFbMemory(void) {
    CERF_LOG("cerf_guest: CerfMapFbMemory entry");
    if (g_FbMemVa) { CERF_LOG_X("cerf_guest: CerfMapFbMemory cached va", g_FbMemVa); return g_FbMemVa; }
    if (g_FbMemPa == 0 || g_FbStride == 0 || g_FbHeight == 0) return NULL;
    /* Map the whole region, not just the primary: the tail past the primary
       (which sits at offset 0) is the DDraw video memory the driver carves
       offscreen surfaces from — shrinking this to primary_size hands video
       surfaces unmapped VAs. */
    ULONG primary_size = g_FbStride * g_FbHeight;
    if (g_FbMemTotal < primary_size) {
        CERF_LOG_X("cerf_guest: CerfMapFbMemory region too small for primary; total", g_FbMemTotal);
        return NULL;
    }
    void* va = VirtualAlloc(0, g_FbMemTotal, MEM_RESERVE, PAGE_NOACCESS);
    if (!va) return NULL;
    if (!VirtualCopy(va, (LPVOID)(g_FbMemPa >> 8), g_FbMemTotal,
                     PAGE_READWRITE | PAGE_NOCACHE | PAGE_PHYSICAL)) {
        VirtualFree(va, 0, MEM_RELEASE);
        return NULL;
    }
    g_FbMemVa = va;
    CERF_LOG_X("cerf_guest: CerfMapFbMemory mapped va", va);
    return va;
}

static ULONG s_RgbMasks_32bpp[3] = { 0x00FF0000u, 0x0000FF00u, 0x000000FFu };
static ULONG s_RgbMasks_16bpp[3] = { 0xF800u,     0x07E0u,     0x001Fu     };

extern "C" ULONG* APIENTRY DrvGetMasks(DHPDEV) {
    CERF_LOG_X("cerf_guest: DrvGetMasks bpp", g_FbBpp);
    return (g_FbBpp == 16) ? s_RgbMasks_16bpp
         : (g_FbBpp == 32) ? s_RgbMasks_32bpp : NULL;
}

extern "C" BOOL APIENTRY DrvEndDoc(SURFOBJ*, FLONG)            { CERF_LOG("cerf_guest: DrvEndDoc"); return TRUE; }
extern "C" BOOL APIENTRY DrvStartDoc(SURFOBJ*, PWSTR, DWORD)   { CERF_LOG("cerf_guest: DrvStartDoc"); return TRUE; }
extern "C" BOOL APIENTRY DrvStartPage(SURFOBJ*)                { CERF_LOG("cerf_guest: DrvStartPage"); return TRUE; }
extern "C" BOOL APIENTRY DrvExclusiveMode(DHPDEV, BOOL)        { CERF_LOG("cerf_guest: DrvExclusiveMode"); return TRUE; }

extern "C" BOOL APIENTRY DrvBitBlt(SURFOBJ*, SURFOBJ*, SURFOBJ*, CLIPOBJ*,
                                    XLATEOBJ*, RECTL*, POINTL*, POINTL*,
                                    BRUSHOBJ*, POINTL*, ROP4);
extern "C" BOOL APIENTRY DrvCopyBits(SURFOBJ*, SURFOBJ*, CLIPOBJ*, XLATEOBJ*,
                                      RECTL*, POINTL*);
extern "C" BOOL APIENTRY DrvAnyBlt(SURFOBJ*, SURFOBJ*, SURFOBJ*, CLIPOBJ*,
                                    XLATEOBJ*, POINTL*, RECTL*, RECTL*, POINTL*,
                                    BRUSHOBJ*, POINTL*, ROP4, ULONG, ULONG);
extern "C" BOOL APIENTRY DrvTransparentBlt(SURFOBJ*, SURFOBJ*, CLIPOBJ*,
                                            XLATEOBJ*, RECTL*, RECTL*, ULONG);
extern "C" BOOL APIENTRY DrvRealizeBrush(BRUSHOBJ*, SURFOBJ*, SURFOBJ*, SURFOBJ*,
                                          XLATEOBJ*, ULONG);
extern "C" BOOL APIENTRY DrvStrokePath(SURFOBJ*, PATHOBJ*, CLIPOBJ*, XFORMOBJ*,
                                        BRUSHOBJ*, POINTL*, LINEATTRS*, MIX);
extern "C" BOOL APIENTRY DrvFillPath(SURFOBJ*, PATHOBJ*, CLIPOBJ*, BRUSHOBJ*,
                                      POINTL*, MIX, FLONG);
extern "C" BOOL APIENTRY DrvPaint(SURFOBJ*, CLIPOBJ*, BRUSHOBJ*, POINTL*, MIX);

extern "C" BOOL APIENTRY CerfDrvGradientFill(SURFOBJ*, CLIPOBJ*, XLATEOBJ*,
                                              TRIVERTEX*, ULONG, PVOID, ULONG,
                                              RECTL*, POINTL*, ULONG);
extern "C" BOOL APIENTRY CerfDrvAlphaBlend(SURFOBJ*, SURFOBJ*, CLIPOBJ*,
                                            XLATEOBJ*, RECTL*, RECTL*, BLENDOBJ*);

static BOOL APIENTRY CerfTraceBitBlt(SURFOBJ* dst, SURFOBJ* src, SURFOBJ* msk,
                                      CLIPOBJ* co, XLATEOBJ* xlo, RECTL* prd,
                                      POINTL* pps, POINTL* ppm, BRUSHOBJ* pbo,
                                      POINTL* ppb, ROP4 rop4) {
    CERF_LOG_X("cerf_guest: DrvBitBlt rop4", rop4);
    CERF_LOG_X("cerf_guest: DrvBitBlt xlo",  xlo);
    CERF_LOG_X("cerf_guest: DrvBitBlt src",  src);
    CERF_LOG_X("cerf_guest: DrvBitBlt dst",  dst);
    CERF_LOG_X("cerf_guest: DrvBitBlt pbo",  pbo);
    return DrvBitBlt(dst, src, msk, co, xlo, prd, pps, ppm, pbo, ppb, rop4);
}
static BOOL APIENTRY CerfTraceCopyBits(SURFOBJ* dst, SURFOBJ* src, CLIPOBJ* co,
                                        XLATEOBJ* xlo, RECTL* prd, POINTL* pps) {
    CERF_LOG_X("cerf_guest: DrvCopyBits xlo", xlo);
    CERF_LOG_X("cerf_guest: DrvCopyBits src", src);
    CERF_LOG_X("cerf_guest: DrvCopyBits dst", dst);
    return DrvCopyBits(dst, src, co, xlo, prd, pps);
}
static BOOL APIENTRY CerfTraceAnyBlt(SURFOBJ* dst, SURFOBJ* src, SURFOBJ* msk,
                                      CLIPOBJ* co, XLATEOBJ* xlo, POINTL* phto,
                                      RECTL* prd, RECTL* prs, POINTL* ppm,
                                      BRUSHOBJ* pbo, POINTL* ppb, ROP4 rop4,
                                      ULONG mode, ULONG flags) {
    CERF_LOG_X("cerf_guest: DrvAnyBlt rop4", rop4);
    CERF_LOG_X("cerf_guest: DrvAnyBlt xlo",  xlo);
    CERF_LOG_X("cerf_guest: DrvAnyBlt mode", mode);
    return DrvAnyBlt(dst, src, msk, co, xlo, phto, prd, prs, ppm, pbo, ppb,
                      rop4, mode, flags);
}
static BOOL APIENTRY CerfTraceTransparentBlt(SURFOBJ* dst, SURFOBJ* src,
                                              CLIPOBJ* co, XLATEOBJ* xlo,
                                              RECTL* prd, RECTL* prs, ULONG tc) {
    CERF_LOG_X("cerf_guest: DrvTransparentBlt xlo", xlo);
    CERF_LOG_X("cerf_guest: DrvTransparentBlt tc",  tc);
    return DrvTransparentBlt(dst, src, co, xlo, prd, prs, tc);
}
static BOOL APIENTRY CerfTraceRealizeBrush(BRUSHOBJ* pbo, SURFOBJ* psoTarget,
                                            SURFOBJ* psoPattern, SURFOBJ* psoMask,
                                            XLATEOBJ* pxlo, ULONG iHatch) {
    CERF_LOG_X("cerf_guest: DrvRealizeBrush pxlo", pxlo);
    CERF_LOG_X("cerf_guest: DrvRealizeBrush iHatch", iHatch);
    return DrvRealizeBrush(pbo, psoTarget, psoPattern, psoMask, pxlo, iHatch);
}
static BOOL APIENTRY CerfTraceStrokePath(SURFOBJ* pso, PATHOBJ* ppo, CLIPOBJ* pco,
                                          XFORMOBJ* pxo, BRUSHOBJ* pbo,
                                          POINTL* pptlBrush, LINEATTRS* plineattrs,
                                          MIX mix) {
    CERF_LOG_X("cerf_guest: DrvStrokePath mix", mix);
    return DrvStrokePath(pso, ppo, pco, pxo, pbo, pptlBrush, plineattrs, mix);
}
static BOOL APIENTRY CerfTraceFillPath(SURFOBJ* pso, PATHOBJ* ppo, CLIPOBJ* pco,
                                        BRUSHOBJ* pbo, POINTL* pptlBrush, MIX mix,
                                        FLONG flOptions) {
    CERF_LOG_X("cerf_guest: DrvFillPath mix", mix);
    return DrvFillPath(pso, ppo, pco, pbo, pptlBrush, mix, flOptions);
}
static BOOL APIENTRY CerfTracePaint(SURFOBJ* pso, CLIPOBJ* pco, BRUSHOBJ* pbo,
                                     POINTL* pptlBrush, MIX mix) {
    CERF_LOG_X("cerf_guest: DrvPaint mix", mix);
    return DrvPaint(pso, pco, pbo, pptlBrush, mix);
}


/* DO NOT delegate TRIVIAL to the engine — CE3 gwes's static TRIVIAL XLATEOBJ
   has a bogus internal palette ptr the engine handler derefs → Data Abort.
   Trivial = no palette anyway, so 0 is correct. */
static ULONG (*g_EngineXlateObj_cGetPalette)(XLATEOBJ*, ULONG, ULONG, ULONG*) = NULL;

static ULONG WINAPI CerfXlateGetPaletteWrap(XLATEOBJ* pxlo, ULONG iPal,
                                             ULONG cPal, ULONG* pPal) {
    if (!pxlo) return 0;
    CERF_LOG_X("cerf_guest: XlateGetPal flXlate", pxlo->flXlate);
    if (pxlo->flXlate == XO_TRIVIAL) return 0;
    if (!g_EngineXlateObj_cGetPalette) return 0;
    return g_EngineXlateObj_cGetPalette(pxlo, iPal, cPal, pPal);
}


/* CE3/CE5/WM5 lack the engine palette pool (13-callback ENGCALLBACKS); these
   supply no-pool semantics for the 3 missing callbacks. DO NOT make Release a
   no-op — gpe.cpp:747 delegates the only free of lib's new ULONG[] palette
   here; a no-op leaks one buffer per brush-realize. */
static BOOL CerfNoPoolGetPalette(ULONG, ULONG**, int*)             { return FALSE; }
static VOID CerfNoPoolAddPalette(ULONG, ULONG*, int)              { }
static VOID CerfNoPoolReleasePalette(ULONG, ULONG* pPalette, int) { delete[] pPalette; }

/* Lib's DrvEnablePDEV writes pgdiinfo->ulVersion = DDI_DRIVER_VERSION (0x00040001
   = CE6) unconditionally. On CE3 (engine expects 0x00020001), this makes engine
   think driver is CE5+ → takes wrong code path. Wrapper patches ulVersion to
   the actual iEngineVersion the engine passed in. */
extern "C" DHPDEV APIENTRY DrvEnablePDEV(DEVMODEW*, LPWSTR, ULONG, HSURF*,
                                          ULONG, ULONG*, ULONG, DEVINFO*,
                                          HDEV, LPWSTR, HANDLE);

static DHPDEV APIENTRY CerfEnablePDEVWrap(
    DEVMODEW* pdm, LPWSTR pwszLogAddress, ULONG cPat, HSURF* phsurfPatterns,
    ULONG cjCaps, ULONG* pdevcaps, ULONG cjDevInfo, DEVINFO* pdi,
    HDEV hdev, LPWSTR pwszDeviceName, HANDLE hDriver) {
    CERF_LOG_X("cerf_guest: CerfEnablePDEVWrap cjCaps", cjCaps);
    CERF_LOG_X("cerf_guest: CerfEnablePDEVWrap cjDevInfo", cjDevInfo);
    DHPDEV result = DrvEnablePDEV(pdm, pwszLogAddress, cPat, phsurfPatterns,
                                   cjCaps, pdevcaps, cjDevInfo, pdi,
                                   hdev, pwszDeviceName, hDriver);
    CERF_LOG_X("cerf_guest: CerfEnablePDEVWrap result", result);
    if (!result || !pdevcaps || cjCaps < sizeof(ULONG) || g_EngineVersion == 0) {
        return result;
    }
    pdevcaps[0] = g_EngineVersion;
    if (g_EngineVersion == 0x00020001u && cjCaps >= 20 * sizeof(ULONG)) {
        /* CE3 GPE lib's exact GDIINFO fill (WINCE300 PRIVATE GPE DDI_IF.CPP:801-817);
           the linked CE6 lib wrote CE6 values at CE6 offsets, and CE3 has no
           flShadeBlendCaps so offset 52+ is shifted. RC_* per ce3 wingdi.h:220-231. */
        pdevcaps[2]  = 64u;
        pdevcaps[3]  = 60u;
        /* CE3 imgdecmp DecompressImageIndirect rejects bpp not in {2,4,8,16,24}
           (imgdecmp.dll @ 0x1124300) -> blank shell bitmaps; report 24, FB stays 32.
           A newer CE found rejecting 32 needs the same downgrade. */
        if (g_FbBpp == 32u) pdevcaps[6] = 24u;
        pdevcaps[9]  = 0x801u | ((g_FbBpp <= 8) ? 0x100u : 0u);
        pdevcaps[13] = 0u;
        pdevcaps[14] = 0u;
        pdevcaps[15] = 0u;
        pdevcaps[16] = 1u;
        pdevcaps[17] = 1u;
        pdevcaps[18] = 1u;
        pdevcaps[19] = 0u;
    }
    return result;
}

extern "C" BOOL APIENTRY DrvEnableDriver(ULONG iEngineVersion,
                                          ULONG cj,
                                          DRVENABLEDATA* pded,
                                          PENGCALLBACKS pCallbacks) {
    CERF_LOG_X("cerf_guest: DrvEnableDriver iEngineVersion", iEngineVersion);
    CERF_LOG_X("cerf_guest: DrvEnableDriver cj", cj);
    if (pded == NULL || pCallbacks == NULL || cj < 27 * sizeof(void*)) return FALSE;

    g_EngineVersion = iEngineVersion;

    BRUSHOBJ_pvAllocRbrush  = pCallbacks->BRUSHOBJ_pvAllocRbrush;
    BRUSHOBJ_pvGetRbrush    = pCallbacks->BRUSHOBJ_pvGetRbrush;
    CLIPOBJ_cEnumStart      = pCallbacks->CLIPOBJ_cEnumStart;
    CLIPOBJ_bEnum           = pCallbacks->CLIPOBJ_bEnum;
    PALOBJ_cGetColors       = pCallbacks->PALOBJ_cGetColors;
    PATHOBJ_vEnumStart      = pCallbacks->PATHOBJ_vEnumStart;
    PATHOBJ_bEnum           = pCallbacks->PATHOBJ_bEnum;
    PATHOBJ_vGetBounds      = pCallbacks->PATHOBJ_vGetBounds;
    g_EngineXlateObj_cGetPalette = pCallbacks->XLATEOBJ_cGetPalette;
    XLATEOBJ_cGetPalette    = CerfXlateGetPaletteWrap;
    EngCreateDeviceSurface  = pCallbacks->EngCreateDeviceSurface;
    EngDeleteSurface        = pCallbacks->EngDeleteSurface;
    EngCreateDeviceBitmap   = pCallbacks->EngCreateDeviceBitmap;
    EngCreatePalette        = pCallbacks->EngCreatePalette;

    if (cj >= 31 * sizeof(void*)) {
        EngGetPaletteFromPool   = pCallbacks->EngGetPaletteFromPool;
        EngAddPaletteToPool     = pCallbacks->EngAddPaletteToPool;
        EngReleasePooledPalette = pCallbacks->EngReleasePooledPalette;
    } else {
        EngGetPaletteFromPool   = CerfNoPoolGetPalette;
        EngAddPaletteToPool     = CerfNoPoolAddPalette;
        EngReleasePooledPalette = CerfNoPoolReleasePalette;
    }

    memset(pded, 0, cj);
    pded->DrvEnablePDEV         = CerfEnablePDEVWrap;
    pded->DrvDisablePDEV        = DrvDisablePDEV;
    pded->DrvEnableSurface      = DrvEnableSurface;
    pded->DrvDisableSurface     = DrvDisableSurface;
    pded->DrvCreateDeviceBitmap = DrvCreateDeviceBitmap;
    pded->DrvDeleteDeviceBitmap = DrvDeleteDeviceBitmap;
    pded->DrvRealizeBrush       = CerfTraceRealizeBrush;
    pded->DrvStrokePath         = CerfTraceStrokePath;
    pded->DrvFillPath           = CerfTraceFillPath;
    pded->DrvPaint              = CerfTracePaint;
    pded->DrvBitBlt             = CerfTraceBitBlt;
    pded->DrvCopyBits           = CerfTraceCopyBits;
    pded->DrvAnyBlt             = CerfTraceAnyBlt;
    pded->DrvTransparentBlt     = CerfTraceTransparentBlt;
    pded->DrvSetPalette         = DrvSetPalette;
    pded->DrvSetPointerShape    = DrvSetPointerShape;
    pded->DrvMovePointer        = DrvMovePointer;
    pded->DrvGetModes           = DrvGetModes;
    pded->DrvRealizeColor       = DrvRealizeColor;
    pded->DrvGetMasks           = DrvGetMasks;
    pded->DrvUnrealizeColor     = DrvUnrealizeColor;
    pded->DrvContrastControl    = DrvContrastControl;
    pded->DrvPowerHandler       = DrvPowerHandler;
    pded->DrvEndDoc             = DrvEndDoc;
    pded->DrvStartDoc           = DrvStartDoc;
    pded->DrvStartPage          = DrvStartPage;
    pded->DrvEscape             = DrvEscape;
    /* Gradient/alpha gated exactly like DeviceEmulator_lcd (sub_17C6048):
       cj==120 -> both, cj==116 -> gradient only. A NULL slot 27 makes gwes
       SetLastError(ERROR_NOT_SUPPORTED) and paint nothing (sub_82378). */
    if (cj >= 30 * sizeof(void*)) {
        pded->DrvGradientFill   = CerfDrvGradientFill;
        pded->DrvAlphaBlend     = CerfDrvAlphaBlend;
        pded->DrvExclusiveMode  = DrvExclusiveMode;
    } else if (cj >= 29 * sizeof(void*)) {
        pded->DrvGradientFill   = CerfDrvGradientFill;
    }
    if (cj >= 31 * sizeof(void*)) {
        pded->DrvDisableDriver  = DrvDisableDriver;
    }
    return TRUE;
}

extern "C" BOOL APIENTRY DllEntryPoint(HANDLE hInst, DWORD reason, LPVOID) {
    if (reason == DLL_PROCESS_ATTACH) {
        CERF_LOG("cerf_guest: DLL_PROCESS_ATTACH");
        CerfReadFbRegs();
    } else if (reason == DLL_PROCESS_DETACH) {
        CERF_LOG("cerf_guest: DLL_PROCESS_DETACH");
    }
    return TRUE;
}
