#include <windows.h>
#include <pkfuncs.h>
#include <winddi.h>

#include "cerf_ddi.h"
#include "cerf_regs_map.h"

#ifndef GCAPS_GRAY16
#define GCAPS_GRAY16 0x01000000u
#endif

#include "cerf/peripherals/cerf_virt/cerf_virt_addr_map.h"
#include "cerf/peripherals/cerf_virt/cerf_virt_color_scheme_regs.h"
#include "cerf/peripherals/cerf_virt/cerf_virt_fb_regs.h"
#include "cerf_dma_arena.h"

#define CERF_GPE_DESC_VA          0x000u
#define CERF_GPE_STATUS           0x004u
#define CERF_GPE_KICK_OFFSET      0x800u
#define CERF_GPE_GRAD_KICK_OFFSET 0x804u
#define CERF_GPE_LINE_KICK_OFFSET 0x808u
#define CERF_GPE_STATUS_DONE      2u

static volatile ULONG* s_fb_regs  = NULL;
static volatile ULONG* s_gpe_cmd  = NULL;
ULONG g_FbWidth   = 0;
ULONG g_FbHeight  = 0;
ULONG g_FbBpp     = 0;
ULONG g_FbStride  = 0;
ULONG g_FbDpi     = 0;
ULONG g_FbRefreshRate = 60;
LONG  g_FbSystemFontHeight = 0;
ULONG g_FbSystemFontPresent = 0;
ULONG g_FbMemPa   = 0;
ULONG g_FbMemTotal = 0;

ULONG g_FbPrimaryReserve = 0;

void* g_FbMemVa   = NULL;
ULONG g_EngineVersion = 0;
ULONG g_OsMajor = 0;

static wchar_t s_module_name[MAX_PATH] = { 0 };
static HMODULE s_hinst = NULL;
extern "C" const wchar_t* CerfInjectedModuleName(void) { return s_module_name; }

extern "C" void CerfSetCarrierName(const wchar_t* name) {
    if (!name) return;
    int i = 0;
    for (; name[i] && i < MAX_PATH - 1; ++i) s_module_name[i] = name[i];
    s_module_name[i] = 0;
}

void CerfReadFbRegs(void) {
    if (s_fb_regs) return;
    s_fb_regs = (volatile ULONG*)CerfMapRegsPage(g_CerfVirtBase + CerfVirt::kFramebufferRegsOffset,
                                                 CerfVirt::kFramebufferRegsSize);
    if (!s_fb_regs) return;
    g_FbWidth  = s_fb_regs[0];
    g_FbHeight = s_fb_regs[1];
    g_FbBpp    = s_fb_regs[2];
    g_FbStride = s_fb_regs[3];
    g_FbMemPa   = s_fb_regs[5];
    g_FbMemTotal = s_fb_regs[7];
    g_FbPrimaryReserve = s_fb_regs[8];
    g_FbDpi      = s_fb_regs[9];
    if (s_fb_regs[10]) g_FbRefreshRate = s_fb_regs[10];
    g_FbSystemFontHeight  = (LONG)s_fb_regs[11];
    g_FbSystemFontPresent = s_fb_regs[12];
}

BOOL CerfMapGpeCmd(void) {
    CERF_LOG_DEV("cerf_guest: CerfMapGpeCmd entry");
    if (s_gpe_cmd) return TRUE;
    s_gpe_cmd = (volatile ULONG*)CerfMapRegsPage(g_CerfVirtBase + CerfVirt::kGpeCmdOffset,
                                                 CerfVirt::kGpeCmdSize);
    return s_gpe_cmd != NULL;
}

extern "C" ULONG CerfGpeBlt(ULONG desc_va) {
    if (!CerfMapGpeCmd()) return (ULONG)-1;
    s_gpe_cmd[CERF_GPE_DESC_VA / 4] = desc_va;
    *(volatile ULONG*)(((volatile UCHAR*)s_gpe_cmd) + CERF_GPE_KICK_OFFSET) = 1u;
    return s_gpe_cmd[CERF_GPE_STATUS / 4];
}

extern "C" ULONG CerfGpeGrad(ULONG desc_va) {
    if (!CerfMapGpeCmd()) return (ULONG)-1;
    s_gpe_cmd[CERF_GPE_DESC_VA / 4] = desc_va;
    *(volatile ULONG*)(((volatile UCHAR*)s_gpe_cmd) + CERF_GPE_GRAD_KICK_OFFSET) = 1u;
    return s_gpe_cmd[CERF_GPE_STATUS / 4];
}

extern "C" ULONG CerfGpeLine(ULONG desc_va) {
    if (!CerfMapGpeCmd()) return (ULONG)-1;
    s_gpe_cmd[CERF_GPE_DESC_VA / 4] = desc_va;
    *(volatile ULONG*)(((volatile UCHAR*)s_gpe_cmd) + CERF_GPE_LINE_KICK_OFFSET) = 1u;
    return s_gpe_cmd[CERF_GPE_STATUS / 4];
}

extern "C" ULONG CerfGpeFbMemBasePa(void) { return g_CerfVirtBase + CerfVirt::kFramebufferMemOffset; }

static volatile ULONG* s_palette_regs = NULL;

extern "C" void CerfPublishPalette(const ULONG* rgb, unsigned first, unsigned count) {
    if (!s_palette_regs)
        s_palette_regs = (volatile ULONG*)CerfMapRegsPage(
            g_CerfVirtBase + CerfVirt::kPaletteOffset, CerfVirt::kPaletteSize);
    if (!s_palette_regs || !rgb) return;
    for (unsigned i = 0; i < count && first + i < CerfVirt::kPaletteEntries; ++i)
        s_palette_regs[first + i] = rgb[i] & 0x00FFFFFFu;
}

void* CerfMapFbMemory(void) {
    if (g_FbMemVa) return g_FbMemVa;
    if (g_FbMemPa == 0 || g_FbStride == 0 || g_FbHeight == 0) return NULL;
    if (g_FbMemTotal < g_FbStride * g_FbHeight) {
        CERF_LOG_X("cerf_guest: CerfMapFbMemory region too small for primary; total", g_FbMemTotal);
        return NULL;
    }
    g_FbMemVa = (void*)(ULONG_PTR)g_FbMemPa;
    return g_FbMemVa;
}

extern "C" void* CerfMapFbWindow(ULONG fb_pa, ULONG bytes) {
    const ULONG page_off  = fb_pa & 0xFFFu;
    const ULONG base_pa   = fb_pa & ~0xFFFu;
    const ULONG map_bytes = (page_off + bytes + 0xFFFu) & ~0xFFFu;
    void* va = VirtualAlloc(0, map_bytes, MEM_RESERVE, PAGE_NOACCESS);
    if (!va) return NULL;
    if (!VirtualCopy(va, (LPVOID)(base_pa >> 8), map_bytes,
                     PAGE_READWRITE | PAGE_NOCACHE | PAGE_PHYSICAL)) {
        VirtualFree(va, 0, MEM_RELEASE);
        return NULL;
    }
    return (void*)((BYTE*)va + page_off);
}

extern "C" void CerfUnmapFbWindow(void* exact_va) {
    if (exact_va) VirtualFree((void*)((ULONG_PTR)exact_va & ~0xFFFu), 0, MEM_RELEASE);
}

static void* g_FbGlobalVa = NULL;
extern "C" void* CerfMapFbGlobal(void) {
    if (g_FbGlobalVa) return g_FbGlobalVa;
    const ULONG base = CerfGpeFbMemBasePa();
    if (base == 0 || g_FbMemTotal < 0x200000u) return NULL;
    g_FbGlobalVa = CerfMapFbWindow(base, g_FbMemTotal);
    return g_FbGlobalVa;
}

static ULONG s_RgbMasks_32bpp[3] = { 0x00FF0000u, 0x0000FF00u, 0x000000FFu };
static ULONG s_RgbMasks_16bpp[3] = { 0xF800u,     0x07E0u,     0x001Fu     };

extern "C" ULONG* APIENTRY DrvGetMasks(DHPDEV) {
    CERF_LOG_X_DEV("cerf_guest: DrvGetMasks bpp", g_FbBpp);
    return (g_FbBpp == 16) ? s_RgbMasks_16bpp
         : (g_FbBpp == 32) ? s_RgbMasks_32bpp : NULL;
}

extern "C" BOOL APIENTRY DrvEndDoc(SURFOBJ*, FLONG)            { CERF_LOG_DEV("cerf_guest: DrvEndDoc"); return TRUE; }
extern "C" BOOL APIENTRY DrvStartDoc(SURFOBJ*, PWSTR, DWORD)   { CERF_LOG_DEV("cerf_guest: DrvStartDoc"); return TRUE; }
extern "C" BOOL APIENTRY DrvStartPage(SURFOBJ*)                { CERF_LOG_DEV("cerf_guest: DrvStartPage"); return TRUE; }
extern "C" BOOL APIENTRY DrvExclusiveMode(DHPDEV, BOOL)        { CERF_LOG_DEV("cerf_guest: DrvExclusiveMode"); return TRUE; }

static BOOL APIENTRY CerfTraceBitBlt(SURFOBJ* dst, SURFOBJ* src, SURFOBJ* msk,
                                      CLIPOBJ* co, XLATEOBJ* xlo, RECTL* prd,
                                      POINTL* pps, POINTL* ppm, BRUSHOBJ* pbo,
                                      POINTL* ppb, ROP4 rop4) {
    CERF_LOG_X_DEV("cerf_guest: DrvBitBlt rop4", rop4);
    CERF_LOG_X_DEV("cerf_guest: DrvBitBlt xlo",  xlo);
    CERF_LOG_X_DEV("cerf_guest: DrvBitBlt src",  src);
    CERF_LOG_X_DEV("cerf_guest: DrvBitBlt dst",  dst);
    CERF_LOG_X_DEV("cerf_guest: DrvBitBlt pbo",  pbo);
    return DrvBitBlt(dst, src, msk, co, xlo, prd, pps, ppm, pbo, ppb, rop4);
}
static BOOL APIENTRY CerfTraceCopyBits(SURFOBJ* dst, SURFOBJ* src, CLIPOBJ* co,
                                        XLATEOBJ* xlo, RECTL* prd, POINTL* pps) {
    CERF_LOG_X_DEV("cerf_guest: DrvCopyBits xlo", xlo);
    CERF_LOG_X_DEV("cerf_guest: DrvCopyBits src", src);
    CERF_LOG_X_DEV("cerf_guest: DrvCopyBits dst", dst);
    return DrvCopyBits(dst, src, co, xlo, prd, pps);
}
static BOOL APIENTRY CerfTraceAnyBlt(SURFOBJ* dst, SURFOBJ* src, SURFOBJ* msk,
                                      CLIPOBJ* co, XLATEOBJ* xlo, POINTL* phto,
                                      RECTL* prd, RECTL* prs, POINTL* ppm,
                                      BRUSHOBJ* pbo, POINTL* ppb, ROP4 rop4,
                                      ULONG mode, ULONG flags) {
    CERF_LOG_X_DEV("cerf_guest: DrvAnyBlt rop4", rop4);
    CERF_LOG_X_DEV("cerf_guest: DrvAnyBlt xlo",  xlo);
    CERF_LOG_X_DEV("cerf_guest: DrvAnyBlt mode", mode);
    return DrvAnyBlt(dst, src, msk, co, xlo, phto, prd, prs, ppm, pbo, ppb,
                      rop4, mode, flags);
}
static BOOL APIENTRY CerfTraceTransparentBlt(SURFOBJ* dst, SURFOBJ* src,
                                              CLIPOBJ* co, XLATEOBJ* xlo,
                                              RECTL* prd, RECTL* prs, ULONG tc) {
    CERF_LOG_X_DEV("cerf_guest: DrvTransparentBlt xlo", xlo);
    CERF_LOG_X_DEV("cerf_guest: DrvTransparentBlt tc",  tc);
    return DrvTransparentBlt(dst, src, co, xlo, prd, prs, tc);
}
static BOOL APIENTRY CerfTraceRealizeBrush(BRUSHOBJ* pbo, SURFOBJ* psoTarget,
                                            SURFOBJ* psoPattern, SURFOBJ* psoMask,
                                            XLATEOBJ* pxlo, ULONG iHatch) {
    CERF_LOG_X_DEV("cerf_guest: DrvRealizeBrush pxlo", pxlo);
    CERF_LOG_X_DEV("cerf_guest: DrvRealizeBrush iHatch", iHatch);
    return DrvRealizeBrush(pbo, psoTarget, psoPattern, psoMask, pxlo, iHatch);
}
static BOOL APIENTRY CerfTracePaint(SURFOBJ* pso, CLIPOBJ* pco, BRUSHOBJ* pbo,
                                     POINTL* pptlBrush, MIX mix) {
    CERF_LOG_X_DEV("cerf_guest: DrvPaint mix", mix);
    return DrvPaint(pso, pco, pbo, pptlBrush, mix);
}

static ULONG (*g_EngineXlateObj_cGetPalette)(XLATEOBJ*, ULONG, ULONG, ULONG*) = NULL;

static ULONG WINAPI CerfXlateGetPaletteWrap(XLATEOBJ* pxlo, ULONG iPal,
                                             ULONG cPal, ULONG* pPal) {
    if (!pxlo) return 0;
    CERF_LOG_X_DEV("cerf_guest: XlateGetPal flXlate", pxlo->flXlate);
    if (pxlo->flXlate == XO_TRIVIAL) return 0;
    if (!g_EngineXlateObj_cGetPalette) return 0;
    return g_EngineXlateObj_cGetPalette(pxlo, iPal, cPal, pPal);
}

static BOOL CerfNoPoolGetPalette(ULONG, ULONG**, int*)             { return FALSE; }
static VOID CerfNoPoolAddPalette(ULONG, ULONG*, int)              { }
static VOID CerfNoPoolReleasePalette(ULONG, ULONG* pPalette, int) { delete[] pPalette; }

extern "C" void CerfStartInputPump(void);
extern "C" void CerfStartServicePump(void);
extern "C" void CerfStartTickProfiler(HMODULE self);
extern "C" void CerfStartDriverInDriver(void);
extern "C" void CerfAdvertiseDisplayPower(void);
extern "C" void CerfStartSync2ShellReplace(void);
extern "C" void CerfApplyRegistryCustomizations(void);

static DHPDEV APIENTRY CerfEnablePDEVWrap(
    DEVMODEW* pdm, LPWSTR pwszLogAddress, ULONG cPat, HSURF* phsurfPatterns,
    ULONG cjCaps, ULONG* pdevcaps, ULONG cjDevInfo, DEVINFO* pdi,
    HDEV hdev, LPWSTR pwszDeviceName, HANDLE hDriver) {
    DHPDEV result = DrvEnablePDEV(pdm, pwszLogAddress, cPat, phsurfPatterns,
                                   cjCaps, pdevcaps, cjDevInfo, pdi,
                                   hdev, pwszDeviceName, hDriver);
    if (result) CerfStartInputPump();
    if (result) CerfStartTickProfiler(s_hinst);
    if (result) CerfStartDriverInDriver();
    if (result) CerfAdvertiseDisplayPower();
    if (result) CerfStartSync2ShellReplace();
    if (result) CerfStartServicePump();
    return result;
}

extern "C" BOOL APIENTRY DrvEnableDriver(ULONG iEngineVersion,
                                          ULONG cj,
                                          DRVENABLEDATA* pded,
                                          PENGCALLBACKS pCallbacks) {
    CERF_LOG_INIT(CERF_LOG_CH_DISPLAY);
    CERF_LOG_X("cerf_guest: DrvEnableDriver iEngineVersion", iEngineVersion);
    CERF_LOG_X("cerf_guest: DrvEnableDriver cj", cj);
    CERF_LOG_X("cerf_guest: DrvEnableDriver slots", cj / sizeof(void*));
    CerfReadFbRegs();
    CerfApplyRegistryCustomizations();

    if (pded == NULL || pCallbacks == NULL || cj < 26 * sizeof(void*)) return FALSE;

    if (!s_module_name[0]) {
        wchar_t full[MAX_PATH];
        DWORD n = GetModuleFileNameW(s_hinst, full, MAX_PATH);
        if (n > 0 && n < MAX_PATH) {
            const wchar_t* base = full;
            for (const wchar_t* p = full; *p; ++p)
                if (*p == L'\\' || *p == L'/') base = p + 1;
            ULONG i = 0;
            for (; base[i] && i < MAX_PATH - 1; ++i) s_module_name[i] = base[i];
            s_module_name[i] = L'\0';
        }
    }
    {
        OSVERSIONINFOW ovi;
        ovi.dwOSVersionInfoSize = sizeof(ovi);
        g_OsMajor = GetVersionExW(&ovi) ? ovi.dwMajorVersion : 5u;
        CerfSetVidBackingByOsMajor(g_OsMajor);
    }

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
    pded->DrvStrokePath         = DrvStrokePath;
    pded->DrvFillPath           = DrvFillPath;
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
    if (cj >= 27 * sizeof(void*)) pded->DrvEscape = DrvEscape;

    if (cj >= 28 * sizeof(void*)) pded->DrvGradientFill  = CerfDrvGradientFill;
    if (cj >= 29 * sizeof(void*)) pded->DrvAlphaBlend    = CerfDrvAlphaBlend;
    if (cj >= 30 * sizeof(void*)) pded->DrvExclusiveMode = DrvExclusiveMode;
    if (cj >= 31 * sizeof(void*)) pded->DrvDisableDriver = DrvDisableDriver;
    return TRUE;
}

extern "C" BOOL APIENTRY DllEntryPoint(HANDLE hInst, DWORD reason, LPVOID) {
    if (reason == DLL_PROCESS_ATTACH) {
        CERF_LOG("cerf_guest: DLL_PROCESS_ATTACH");
        s_hinst = (HMODULE)hInst;
        CerfArenaProcessAttach();
    } else if (reason == DLL_PROCESS_DETACH) {
        CERF_LOG("cerf_guest: DLL_PROCESS_DETACH");
    }
    return TRUE;
}
