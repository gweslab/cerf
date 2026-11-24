#include <windows.h>
#include "cerf_wp7_gpu_budget.h"
#include "cerf_ddhal_wp7.h"
#include "cerf_debug_log.h"
#include "cerf_wp7_coredll.h"
#include "cerf_wp7_yuv.h"
#include "main.h"
#include "cerfcore/peripherals/cerf_virt/cerf_virt_fb_regs.h"

#define CERF_WP7_SLAB_ALIGN       0x2000u
#define CERF_WP7_TRUECOLOR_RANK   1000u
#define CERF_WP7_DEFAULT_SLABS    12u
#define CERF_WP7_SLAB_MIN_BUFFERS 4u
#define CERF_WP7_WVGA_LONG        800u
#define CERF_WP7_WVGA_SHORT       480u
#define CERF_WP7_HD_WIDTH         1280u
#define CERF_WP7_HD_HEIGHT        720u
#define CERF_WP7_FOURCC_12BIT     12u
#define CERF_WP7_FOURCC_16BIT     16u
#define CERF_WP7_BPP_565          16u
#define CERF_WP7_BPP_8888         32u

static const wchar_t kCerfWp7CompositorKey[]  = L"SYSTEM\\GWE\\Compositor";
static const wchar_t kCerfWp7SlabCountValue[] = L"SlabCount";

typedef struct {
    DWORD slab;
    DWORD count;
} CerfWp7Slabs;

static DWORD CerfWp7SlabAlign(DWORD v) { return (v + CERF_WP7_SLAB_ALIGN - 1u) & ~(CERF_WP7_SLAB_ALIGN - 1u); }

static DWORD CerfWp7Larger(DWORD a, DWORD b) { return a > b ? a : b; }

static DWORD CerfWp7RgbSlab(DWORD w, DWORD h, DWORD bpp) {
    return CerfWp7SlabAlign(CerfWp7RgbSurfaceBytes(w, h, bpp));
}

static DWORD CerfWp7FourCcSlab(DWORD fourcc, DWORD w, DWORD h) {
    CerfWp7Layout layout;
    CerfWp7YuvLayout(fourcc, w, h, &layout);
    return CerfWp7SlabAlign(layout.size);
}

static DWORD CerfWp7SlabCount(void) {
    HKEY  hk;
    DWORD value = 0;
    DWORD bytes = sizeof(value);
    DWORD count = CERF_WP7_DEFAULT_SLABS;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, kCerfWp7CompositorKey, 0, 0, &hk) != ERROR_SUCCESS) return count;
    if (RegQueryValueExW(hk, kCerfWp7SlabCountValue, NULL, NULL, (BYTE*)&value, &bytes) == ERROR_SUCCESS)
        count = value;
    RegCloseKey(hk);
    return count;
}

static BOOL CerfWp7TrueColorCompositor(void) {
    DWORD rank = 0;
    CerfWp7Api()->chassis_rank(&rank);
    return rank >= CERF_WP7_TRUECOLOR_RANK;
}

static DWORD CerfWp7TrueColorSlab(DWORD per_mode) {
    DWORD                    formats = 0;
    const Wp7_FOURCC_FORMAT* fourcc  = CerfWp7FourCcFormats(&formats);
    DWORD                    slab    = per_mode;
    DWORD                    i;
    for (i = 0; i < formats; ++i) {
        if (fourcc[i].dwBitCount == CERF_WP7_FOURCC_12BIT)
            slab = CerfWp7Larger(slab, CerfWp7FourCcSlab(fourcc[i].dwFourCC, CERF_WP7_HD_WIDTH, CERF_WP7_HD_HEIGHT));
        else if (fourcc[i].dwBitCount == CERF_WP7_FOURCC_16BIT)
            slab = CerfWp7Larger(slab, 2u * CerfWp7FourCcSlab(fourcc[i].dwFourCC, CERF_WP7_WVGA_LONG,
                                                               CERF_WP7_WVGA_SHORT));
    }
    slab = CerfWp7Larger(slab, CerfWp7RgbSlab(CERF_WP7_WVGA_LONG, CERF_WP7_WVGA_SHORT, CERF_WP7_BPP_8888));
    slab = CerfWp7Larger(slab, CerfWp7RgbSlab(CERF_WP7_WVGA_SHORT, CERF_WP7_WVGA_LONG, CERF_WP7_BPP_8888));
    slab = CerfWp7Larger(slab, 2u * CerfWp7RgbSlab(CERF_WP7_WVGA_LONG, CERF_WP7_WVGA_SHORT, CERF_WP7_BPP_565));
    return CerfWp7Larger(slab, 2u * CerfWp7RgbSlab(CERF_WP7_WVGA_SHORT, CERF_WP7_WVGA_LONG, CERF_WP7_BPP_565));
}

static DWORD CerfWp7HighColorSlab(DWORD per_mode) {
    DWORD                    formats = 0;
    const Wp7_FOURCC_FORMAT* fourcc  = CerfWp7FourCcFormats(&formats);
    DWORD                    slab    = per_mode;
    DWORD                    i;
    for (i = 0; i < formats; ++i)
        if (fourcc[i].dwBitCount == CERF_WP7_FOURCC_12BIT || fourcc[i].dwBitCount == CERF_WP7_FOURCC_16BIT)
            slab = CerfWp7Larger(slab, CerfWp7FourCcSlab(fourcc[i].dwFourCC, CERF_WP7_WVGA_LONG,
                                                         CERF_WP7_WVGA_SHORT));
    slab = CerfWp7Larger(slab, CerfWp7RgbSlab(CERF_WP7_WVGA_LONG, CERF_WP7_WVGA_SHORT, CERF_WP7_BPP_565));
    return CerfWp7Larger(slab, CerfWp7RgbSlab(CERF_WP7_WVGA_SHORT, CERF_WP7_WVGA_LONG, CERF_WP7_BPP_565));
}

static CerfWp7Slabs CerfWp7CompositorSlabs(DWORD w, DWORD h, BOOL truecolor, DWORD registry_slabs) {
    const DWORD  mode565  = CerfWp7RgbSlab(w, h, CERF_WP7_BPP_565);
    const DWORD  mode8888 = CerfWp7RgbSlab(w, h, CERF_WP7_BPP_8888);
    const DWORD  per_mode = truecolor ? CerfWp7Larger(2u * mode565, mode8888) : mode565;
    CerfWp7Slabs s;
    s.slab = truecolor ? CerfWp7TrueColorSlab(per_mode) : CerfWp7HighColorSlab(per_mode);
    DWORD buffers = s.slab / per_mode;
    if (truecolor && mode8888 <= s.slab - buffers * per_mode) ++buffers;
    s.count = CerfWp7Larger(registry_slabs, CERF_WP7_SLAB_MIN_BUFFERS -
                                                (CERF_WP7_SLAB_MIN_BUFFERS * buffers - CERF_WP7_SLAB_MIN_BUFFERS) /
                                                    buffers);
    return s;
}

static BOOL CerfWp7NeedsMore(const CerfWp7Slabs* a, const CerfWp7Slabs* b) {
    if (a->count == b->count) return a->slab > b->slab;
    return a->count * a->slab > b->count * b->slab;
}

static BOOL CerfWp7ModeFitsGpuBudget(DWORD width, DWORD height) {
    const BOOL         truecolor = CerfWp7TrueColorCompositor();
    const DWORD        slabs     = CerfWp7SlabCount();
    const CerfWp7Slabs mode      = CerfWp7CompositorSlabs(width, height, truecolor, slabs);
    const CerfWp7Slabs panel     = CerfWp7CompositorSlabs(CerfReadFbReg(cerfcore::CerfVirt::kFbRegPanelWidth),
                                                          CerfReadFbReg(cerfcore::CerfVirt::kFbRegPanelHeight),
                                                          truecolor, slabs);
    CERF_LOG_X("cerf_guest: WP7 compositor slab bytes", mode.slab);
    CERF_LOG_X("cerf_guest: WP7 compositor slab count", mode.count);
    CERF_LOG_X("cerf_guest: WP7 compositor panel slab bytes", panel.slab);
    return !CerfWp7NeedsMore(&mode, &panel);
}

void CerfWp7FitGpuBudget(void) {
    if (CerfWp7ModeFitsGpuBudget(g_FbWidth, g_FbHeight)) return;
    CERF_LOG_X("cerf_guest: WP7 compositor memory past the panel budget, width", g_FbWidth);
    CERF_LOG_X("cerf_guest: WP7 compositor memory past the panel budget, height", g_FbHeight);
    CerfWriteFbReg(cerfcore::CerfVirt::kFbRegGpuBudgetCap, 1u);
    CerfReloadFbGeometry();
}
