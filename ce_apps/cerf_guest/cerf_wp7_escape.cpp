#include <windows.h>
#include "cerf_wp7_escape.h"
#include "cerf_ddgpe.h"
#include "cerf_debug_log.h"
#include "cerf_wp7_coredll.h"
#include "cerf_wp7_yuv.h"
#include "main.h"
#include "cerfcore/lcd/qcom_tile_layout.h"
#include "cerfcore/peripherals/cerf_virt/cerf_virt_fb_regs.h"

#define CERF_WP7_ESC_QUERY_SUPPORT     8u
#define CERF_WP7_ESC_SET_GAMMA         6201u
#define CERF_WP7_ESC_GET_GAMMA         6202u
#define CERF_WP7_ESC_BACKLIGHT         0x000186E6u
#define CERF_WP7_ESC_186E7             0x000186E7u
#define CERF_WP7_ESC_LOWER_STRIP       0x000186EBu
#define CERF_WP7_ESC_PANEL_INFO        0x010100FCu
#define CERF_WP7_ESC_SURFACE_DESC      0x003D1001u
#define CERF_WP7_ESC_DISPLAY_MODE      0x003D1002u
#define CERF_WP7_ESC_MAP_METADATA      0x003D1003u
#define CERF_WP7_ESC_UNMAP_METADATA    0x003D1004u
#define CERF_WP7_ESC_PAD_TILED         0x003D1005u

#define CERF_WP7_DEFAULT_GAMMA         1500u
#define CERF_WP7_REGISTRY_GAMMA        2330u
#define CERF_WP7_GAMMA_MIN             1000u
#define CERF_WP7_GAMMA_MAX             3000u
#define CERF_WP7_DISPLAY_MODE_BYTES    16u
#define CERF_WP7_PANEL_INFO_BYTES      12u
#define CERF_WP7_SURFACE_DESC_BYTES    44u
#define CERF_WP7_REFRESH_SCALE         1000u
#define CERF_WP7_FLOAT_BITS_0_01       0x3C23D70Au
#define CERF_WP7_FLOAT_SIGN            0x80000000u
#define CERF_WP7_FLOAT_BITS_NEG_INF    0xFF800000u
#define CERF_WP7_BACKLIGHT_PERCENT     100u
#define CERF_WP7_FLOAT_MANTISSA_BITS   23u
#define CERF_WP7_FLOAT_MANTISSA_MASK   0x007FFFFFu
#define CERF_WP7_FLOAT_HIDDEN_BIT      0x00800000u
#define CERF_WP7_FLOAT_EXPONENT_MASK   0xFFu
#define CERF_WP7_FLOAT_EXPONENT_BIAS   150
#define CERF_WP7_UINT_SATURATED        0xFFFFFFFFu
#define CERF_WP7_FLOAT_SHIFT_FITS      8

#define CERF_WP7_DESC_WIDTH            0
#define CERF_WP7_DESC_HEIGHT           1
#define CERF_WP7_DESC_BYTES            2
#define CERF_WP7_DESC_STRIDE           3
#define CERF_WP7_DESC_PLANES           4
#define CERF_WP7_DESC_CLASS            8
#define CERF_WP7_DESC_VA               9
#define CERF_WP7_DESC_GPU              10

#define CERF_WP7_CLASS_565             0u
#define CERF_WP7_CLASS_8880            4u
#define CERF_WP7_CLASS_8888            5u
#define CERF_WP7_CLASS_OTHER           12u

#define CERF_WP7_STRIP_WIDTH           480u
#define CERF_WP7_STRIP_TOP             800u

#define CERF_WP7_META_MAP_BYTES        36u
#define CERF_WP7_META_PLANE_ALIGN      8192u
#define CERF_WP7_VM_RESERVE            0x2000u
#define CERF_WP7_VM_RELEASE            0x8000u
#define CERF_WP7_VM_NOACCESS           0x01u
#define CERF_WP7_VM_RW_NOCACHE         0x204u
#define CERF_WP7_PAD_IN_WIDTH          0
#define CERF_WP7_PAD_IN_HEIGHT         1
#define CERF_WP7_PAD_IN_CHROMA         4

static const wchar_t kCerfWp7GammaKey[]   = L"System\\GDI\\Gamma";
static const wchar_t kCerfWp7GammaValue[] = L"Gamma Value";

static DWORD g_Wp7Gamma   = CERF_WP7_DEFAULT_GAMMA;
static DWORD g_Wp7AaGamma = 0;

static DWORD CerfWp7ClampGamma(DWORD gamma) {
    if (gamma <= CERF_WP7_GAMMA_MIN) return CERF_WP7_GAMMA_MIN;
    return gamma >= CERF_WP7_GAMMA_MAX ? CERF_WP7_GAMMA_MAX : gamma;
}

static DWORD CerfWp7RegistryGamma(void) {
    HKEY  hk;
    DWORD gamma = CERF_WP7_REGISTRY_GAMMA;
    DWORD bytes = sizeof(gamma);
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, kCerfWp7GammaKey, 0, 0, &hk) != ERROR_SUCCESS) return gamma;
    RegQueryValueExW(hk, kCerfWp7GammaValue, NULL, NULL, (BYTE*)&gamma, &bytes);
    RegCloseKey(hk);
    return CerfWp7ClampGamma(gamma);
}

ULONG CerfWp7TextGammaAa(void) {
    if (!g_Wp7AaGamma) g_Wp7AaGamma = CerfWp7RegistryGamma();
    return g_Wp7AaGamma;
}

ULONG CerfWp7TextGammaClearType(void) { return g_Wp7Gamma; }

static ULONG CerfWp7MetaOffset(DDGPESurf* s) {
    const ULONG w = ((ULONG)s->Width() + cerfcore::qcom_tile::kStrideAlign - 1u) &
                    ~(cerfcore::qcom_tile::kStrideAlign - 1u);
    const ULONG h = (ULONG)s->Height();
    const ULONG luma = ((((h + cerfcore::qcom_tile::kHeight - 1u) & ~(cerfcore::qcom_tile::kHeight - 1u)) * w +
                        CERF_WP7_META_PLANE_ALIGN - 1u) & ~(CERF_WP7_META_PLANE_ALIGN - 1u));
    const ULONG chroma = (((((h >> 1) + cerfcore::qcom_tile::kHeight - 1u) & ~(cerfcore::qcom_tile::kHeight - 1u)) * w +
                          CERF_WP7_META_PLANE_ALIGN - 1u) & ~(CERF_WP7_META_PLANE_ALIGN - 1u));
    return luma + chroma;
}

static ULONG CerfWp7MapMetadata(SURFOBJ* pso, ULONG cjOut, DWORD* out) {
    if (!out || cjOut != sizeof(DWORD)) return 0;
    out[0] = 0;
    DDGPESurf* s = pso ? (DDGPESurf*)pso->dhsurf : NULL;
    if (!s) return 0;
    const CerfWp7Coredll* vm     = CerfWp7Api();
    const HANDLE          caller = (HANDLE)vm->caller_vm();
    LPVOID va = vm->virtual_alloc_ex(caller, NULL, CERF_WP7_META_MAP_BYTES, CERF_WP7_VM_RESERVE,
                                     CERF_WP7_VM_NOACCESS);
    if (!va) return 0;
    if (!vm->virtual_copy_ex(caller, va, GetCurrentProcess(), (BYTE*)s->Buffer() + CerfWp7MetaOffset(s),
                             CERF_WP7_META_MAP_BYTES, CERF_WP7_VM_RW_NOCACHE)) {
        vm->virtual_free_ex(caller, va, 0, CERF_WP7_VM_RELEASE);
        return 0;
    }
    out[0] = (DWORD)va;
    return 1;
}

static BOOL CerfWp7LowerStripFits(ULONG cjIn, const DWORD* in) {
    GPESurf* primary = GetGPE()->PrimarySurface();
    if (cjIn != CERF_WP7_SURFACE_DESC_BYTES || !in || !primary || !in[CERF_WP7_DESC_VA]) return FALSE;
    if (in[CERF_WP7_DESC_CLASS] != CERF_WP7_CLASS_8880 || in[CERF_WP7_DESC_WIDTH] != CERF_WP7_STRIP_WIDTH)
        return FALSE;
    return (ULONG)primary->Height() > CERF_WP7_STRIP_TOP &&
           in[CERF_WP7_DESC_HEIGHT] == (ULONG)primary->Height() - CERF_WP7_STRIP_TOP;
}

static BOOL CerfWp7Handles(DWORD code) {
    switch (code) {
        case CERF_WP7_ESC_SET_GAMMA:
        case CERF_WP7_ESC_GET_GAMMA:
        case CERF_WP7_ESC_BACKLIGHT:
        case CERF_WP7_ESC_186E7:
        case CERF_WP7_ESC_LOWER_STRIP:
        case CERF_WP7_ESC_PANEL_INFO:
        case CERF_WP7_ESC_SURFACE_DESC:
        case CERF_WP7_ESC_DISPLAY_MODE:
        case CERF_WP7_ESC_MAP_METADATA:
        case CERF_WP7_ESC_UNMAP_METADATA:
        case CERF_WP7_ESC_PAD_TILED:
            return TRUE;
    }
    return FALSE;
}

static BOOL CerfWp7FloatAtMost0_01(DWORD bits) {
    if (bits & CERF_WP7_FLOAT_SIGN) return bits <= CERF_WP7_FLOAT_BITS_NEG_INF;
    return bits <= CERF_WP7_FLOAT_BITS_0_01;
}

static DWORD CerfWp7BacklightPercent(DWORD level_bits) {
    if (CerfWp7FloatAtMost0_01(level_bits)) return 0;
    const DWORD exponent = (level_bits >> CERF_WP7_FLOAT_MANTISSA_BITS) & CERF_WP7_FLOAT_EXPONENT_MASK;
    if (exponent == CERF_WP7_FLOAT_EXPONENT_MASK) return CERF_WP7_UINT_SATURATED;
    DWORD q     = ((level_bits & CERF_WP7_FLOAT_MANTISSA_MASK) | CERF_WP7_FLOAT_HIDDEN_BIT) * CERF_WP7_BACKLIGHT_PERCENT;
    LONG  scale = (LONG)exponent - CERF_WP7_FLOAT_EXPONENT_BIAS;
    while (q >= (CERF_WP7_FLOAT_HIDDEN_BIT << 1)) {
        DWORD shift = 0;
        while ((q >> shift) >= (CERF_WP7_FLOAT_HIDDEN_BIT << 1)) ++shift;
        const DWORD rem  = q & ((1u << shift) - 1u);
        const DWORD half = 1u << (shift - 1u);
        q >>= shift;
        scale += (LONG)shift;
        if (rem > half || (rem == half && (q & 1u))) ++q;
    }
    if (scale >= 0) return (scale > CERF_WP7_FLOAT_SHIFT_FITS) ? CERF_WP7_UINT_SATURATED : q << scale;
    return (-scale >= 32) ? 0u : q >> (DWORD)(-scale);
}

static BOOL CerfWp7PersistGamma(DWORD gamma) {
    HKEY  hk;
    DWORD disposition;
    if (RegCreateKeyExW(HKEY_LOCAL_MACHINE, kCerfWp7GammaKey, 0, NULL, 0, 0, NULL, &hk,
                        &disposition) != ERROR_SUCCESS)
        return FALSE;
    const LONG rc = RegSetValueExW(hk, kCerfWp7GammaValue, 0, REG_DWORD, (const BYTE*)&gamma,
                                   sizeof(gamma));
    RegCloseKey(hk);
    return rc == ERROR_SUCCESS;
}

static ULONG CerfWp7FormatClass(EGPEFormat format) {
    switch (format) {
        case gpe16Bpp: return CERF_WP7_CLASS_565;
        case gpe24Bpp: return CERF_WP7_CLASS_8880;
        case gpe32Bpp: return CERF_WP7_CLASS_8888;
        default:       return CERF_WP7_CLASS_OTHER;
    }
}

static ULONG CerfWp7DescribeSurface(SURFOBJ* pso, ULONG cjOut, DWORD* out) {
    if (cjOut != CERF_WP7_SURFACE_DESC_BYTES || !out || !pso) return 0;
    DDGPESurf* s = (DDGPESurf*)pso->dhsurf;
    if (!s) {
        out[CERF_WP7_DESC_WIDTH]  = (DWORD)pso->sizlBitmap.cx;
        out[CERF_WP7_DESC_HEIGHT] = (DWORD)pso->sizlBitmap.cy;
        out[CERF_WP7_DESC_VA]     = (DWORD)pso->pvBits;
        out[CERF_WP7_DESC_GPU]    = 0;
        out[CERF_WP7_DESC_STRIDE] = (DWORD)pso->lDelta;
        out[CERF_WP7_DESC_CLASS]  = (pso->iBitmapFormat == BMF_16BPP) ? CERF_WP7_CLASS_565
                                                                     : CERF_WP7_CLASS_8888;
        return 1;
    }
    out[CERF_WP7_DESC_VA]         = (DWORD)s->Buffer();
    out[CERF_WP7_DESC_WIDTH]      = (DWORD)s->Width();
    out[CERF_WP7_DESC_HEIGHT]     = (DWORD)s->Height();
    out[CERF_WP7_DESC_GPU]        = s->PhysicalAddress();
    out[CERF_WP7_DESC_STRIDE]     = (DWORD)s->Stride();
    out[CERF_WP7_DESC_BYTES]      = s->SurfaceBytes();
    out[CERF_WP7_DESC_PLANES]     = s->CbOffset();
    out[CERF_WP7_DESC_PLANES + 1] = s->ChromaStride();
    out[CERF_WP7_DESC_PLANES + 2] = s->CrOffset();
    out[CERF_WP7_DESC_PLANES + 3] = s->ChromaStride();
    out[CERF_WP7_DESC_CLASS]      = s->YuvCode() ? CerfWp7DescClass(s->YuvCode()) : CerfWp7FormatClass(s->Format());
    return 1;
}

BOOL CerfWp7Escape(SURFOBJ* pso, ULONG iEsc, ULONG cjIn, PVOID pvIn, ULONG cjOut, PVOID pvOut,
                   ULONG* pRet) {
    DWORD* in  = (DWORD*)pvIn;
    DWORD* out = (DWORD*)pvOut;
    *pRet = 0;
    switch (iEsc) {
        case CERF_WP7_ESC_QUERY_SUPPORT:
            if (!in || cjIn < sizeof(DWORD) || !CerfWp7Handles(in[0])) return FALSE;
            *pRet = 1;
            return TRUE;
        case CERF_WP7_ESC_GET_GAMMA:
            if (out) out[0] = g_Wp7Gamma;
            *pRet = 1;
            return TRUE;
        case CERF_WP7_ESC_SET_GAMMA:
            if (in && in[0] && !CerfWp7PersistGamma(cjIn)) return TRUE;
            g_Wp7Gamma   = cjIn;
            g_Wp7AaGamma = CerfWp7ClampGamma(cjIn);
            *pRet = 1;
            return TRUE;
        case CERF_WP7_ESC_BACKLIGHT:
            if (out && cjOut >= sizeof(DWORD)) out[0] = 0;
            if (in && cjIn >= sizeof(DWORD)) {
                CerfWriteFbReg(cerfcore::CerfVirt::kFbRegBacklightPercent, CerfWp7BacklightPercent(in[0]));
                *pRet = 1;
            }
            return TRUE;
        case CERF_WP7_ESC_186E7:
            return TRUE;
        case CERF_WP7_ESC_LOWER_STRIP:
            if (CerfWp7LowerStripFits(cjIn, in))
                CERF_FATAL("cerf_guest: WP7 lower display strip below line 800 is not implemented - halting");
            return TRUE;
        case CERF_WP7_ESC_PANEL_INFO:
            if (!out || cjOut < CERF_WP7_PANEL_INFO_BYTES) {
                SetLastError(ERROR_INVALID_PARAMETER);
                return TRUE;
            }
            out[0] = g_FbWidth;
            out[1] = g_FbHeight;
            out[2] = g_FbBpp;
            *pRet  = 1;
            return TRUE;
        case CERF_WP7_ESC_SURFACE_DESC:
            *pRet = CerfWp7DescribeSurface(pso, cjOut, out);
            return TRUE;
        case CERF_WP7_ESC_DISPLAY_MODE: {
            GPESurf* primary = GetGPE()->PrimarySurface();
            if (primary && out && cjOut == CERF_WP7_DISPLAY_MODE_BYTES) {
                out[0] = (DWORD)primary->Width();
                out[1] = (DWORD)primary->Height();
                out[2] = g_FbRefreshRate * CERF_WP7_REFRESH_SCALE;
                out[3] = CERF_WP7_REFRESH_SCALE;
                *pRet  = 1;
            }
            return TRUE;
        }
        case CERF_WP7_ESC_MAP_METADATA:
            *pRet = CerfWp7MapMetadata(pso, cjOut, out);
            return TRUE;
        case CERF_WP7_ESC_UNMAP_METADATA: {
            if (!in || cjIn != sizeof(DWORD)) return TRUE;
            const CerfWp7Coredll* vm = CerfWp7Api();
            *pRet = vm->virtual_free_ex((HANDLE)vm->caller_vm(), (LPVOID)in[0], 0, CERF_WP7_VM_RELEASE) ? 1 : 0;
            return TRUE;
        }
        case CERF_WP7_ESC_PAD_TILED: {
            DDGPESurf* s = pso ? (DDGPESurf*)pso->dhsurf : NULL;
            if (!in || cjIn != sizeof(DWORD) || !s) return TRUE;
            if (s->YuvCode() == WP7_CODE_QTF1 && s->Buffer())
                CerfWp7PadTiled((BYTE*)s->Buffer(), in[CERF_WP7_PAD_IN_CHROMA], in[CERF_WP7_PAD_IN_WIDTH],
                                in[CERF_WP7_PAD_IN_HEIGHT]);
            *pRet = 1;
            return TRUE;
        }
    }
    return FALSE;
}
