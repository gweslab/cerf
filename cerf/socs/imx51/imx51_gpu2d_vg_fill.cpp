#define NOMINMAX
#include "imx51_gpu2d_vg_fill.h"

#include "../../core/cerf_emulator.h"
#include "../../core/log.h"
#include "../../boards/board_context.h"
#include "imx51_gpu2d_rasterizer.h"
#include "imx51_gpu2d_stroker.h"
#include "imx51_gpu2d_regfile.h"
#include "imx51_gpu2d_gradw_sampler.h"

#include <algorithm>

namespace {
using namespace imx51_g2d_regfile;
constexpr uint32_t kMode  = 0x6Eu;  /* VGV2_MODE: STROKE[8], CAP[5:4], JOIN[7:6], EXPONENTADD[23:18] */
constexpr uint32_t kXf    = 0x50u;  /* VGV2 XF affine XFXX..XFYA = 0x50-0x55 */
constexpr uint32_t kMiter = 0x66u;  /* VGV2 MITER = -cos(2*asin(1/miterLimit)) (sub_41C5B1B8) */
}  // namespace

REGISTER_SERVICE(Imx51Gpu2dVgFill);

bool Imx51Gpu2dVgFill::ShouldRegister() {
    auto* bd = emu_.TryGet<BoardContext>();
    return bd && bd->GetSoc() == SocFamily::iMX51;
}

void Imx51Gpu2dVgFill::Halt(const uint32_t (&regs)[0x100], const char* why,
                            uint32_t addr, uint32_t data) const {
    LOG(Caution, "[GPU2D-VGFILL] %s at 0x%08X (value 0x%08X)\n", why, addr, data);
    (void)regs;
    CerfFatalExit(CERF_FATAL_RUNTIME_ERROR);
}

/* Every un-modeled paint/blend/dest mode halts (FATAL-first). */
void Imx51Gpu2dVgFill::Flush(const uint32_t (&regs)[0x100], bool bbox_live) {
    auto& rast = emu_.Get<Imx51Gpu2dRasterizer>();
    if (!rast.HasGeometry()) return;
    const bool stroke = (regs[kMode] & (1u << 8)) != 0u;  /* VGV2_MODE.STROKE */
    /* G2D_GRADIENT bits (vgregs_z160.h:780-786): INSTRUCTIONS[2:0], ENABLE[6],
       ENABLE2[7], SEL[8]. ENABLE-only, count masked out = 0x40 = the gradient program. */
    const bool gradw_grad = (regs[0xD0] & ~7u) == 0x40u;
    if (regs[0xD0] & 0xC0u) {
        if (!gradw_grad)
            Halt(regs, "GRADW ENABLE2 paint (image-paint composite not in VG-fill)",
                 0xD0u, regs[0xD0]);
        if (stroke)
            Halt(regs, "GRADW gradient paint on a stroke (not modeled)", 0x6Eu, regs[kMode]);
        /* INST0..INST(INSTRUCTIONS) run through the shared GRADW ISA evaluator, which
           halts on any un-modeled opcode/GRADREG - so no exact INST-word gate here. */
        /* TEXCFG (REG_GRADW_TEXCFG): FORMAT[15:12] must be 7 (G2D_8888); BILIN[21] /
           PREMULTIPLY[23] / TEX2D[28] and WRAPU/V[17:20] (CLAMP=0/REPEAT=1) are handled by
           the sampler. TILED[16] / SRGB[22] / SWAP*[24:27,29] stay unmodeled -> must be 0;
           WRAP MIRROR(2)/BORDER(3) unmodeled. */
        const uint32_t tc = regs[0xD1];
        if (((tc >> 12) & 0xFu) != 7u || (tc & 0x2F410000u) ||
            ((tc >> 17) & 0x3u) > 1u || ((tc >> 19) & 0x3u) > 1u)
            Halt(regs, "GRADW texture config (not fmt7, or tiled/mirror-wrap/srgb/swap)", 0xD1u, tc);
        if ((regs[0xD2] & 0x7FFu) == 0u || ((regs[0xD2] >> 11) & 0x7FFu) == 0u)
            Halt(regs, "GRADW texture zero size", 0xD2u, regs[0xD2]);
        if (regs[0xD3] == 0u)
            Halt(regs, "GRADW TEXBASE null bind", 0xD3u, 0);
    }
    const uint32_t bcfg = regs[0x11];          /* G2D_BLENDERCFG (vgregs_z160.h:356-363) */
    if (bcfg & (1u << 5)) {                    /* ENABLE: single-pass A0/C0 program only */
        if (bcfg & 0x1Fu)                      /* PASSES[2:0] / ALPHAPASSES[4:3] */
            Halt(regs, "G2D multi-pass blend (not modeled)", 0x11u, bcfg);
        if (bcfg & 0x180u)                     /* OBS_DIVALPHA[7] / NOMASK[8] */
            Halt(regs, "G2D blender DIVALPHA/NOMASK (not modeled)", 0x11u, bcfg);
        /* OBS_ENABLE[8] ambient; PREMULTIPLYDST[14] modeled in BlendPixel. */
        if (regs[0xC] & ~0x4100u)
            Halt(regs, "G2D ALPHABLEND modulation (not modeled)", 0xCu, regs[0xC]);
    }
    /* G2D_ROP: 0 = power-on, 0x404 = the surface-init ambient (sub_41C61DB4). */
    if (regs[0xD] != 0u && regs[0xD] != 0x404u)
        Halt(regs, "G2D ROP (not modeled)", 0xDu, regs[0xD]);
    if (regs[0x10] != 0xFFFFFFu)               /* G2D_MASK identity wrap */
        Halt(regs, "G2D_MASK non-identity wrap (not modeled)", 0x10u, regs[0x10]);
    /* VGV2 SCALE/BIAS = the path-data interpretation pair (context init writes 1.0/0.0). */
    if (regs[0x5E] != 0x3F800000u || regs[0x5F] != 0u)
        Halt(regs, "VGV2 path SCALE/BIAS non-identity (not modeled)", 0x5Eu, regs[0x5E]);
    /* VG solid fill = COLOR|VGMODE (0x11) or the COPYCOORD rider (0x19); the CONFIG
       gate below halts any source-fetch enable so COPYCOORD has nothing to route. */
    if (regs[0xF] != 0x11u && regs[0xF] != 0x19u)
        Halt(regs, "G2D INPUT mode (not modeled)", 0xFu, regs[0xF]);
    /* G2D_CONFIG: 0 / ARGBMASK-all (0xF000) flat fills; DST[0]=1 = the blend DEST read. */
    if (regs[0xE] != 0u && regs[0xE] != 0xF000u && regs[0xE] != 0x1u)
        Halt(regs, "G2D CONFIG mode (not modeled)", 0xEu, regs[0xE]);
    if ((regs[0x28] & 3u) > 1u)                /* VGV1_CFG2.AAMODE */
        Halt(regs, "VGV1 AAMODE (not modeled)", 0x28u, regs[0x28]);
    const uint32_t cfg0 = regs[0x1];
    if (((cfg0 >> 12) & 0xFu) != 7u)           /* G2D_CFG0.FORMAT: G2D_8888 only */
        Halt(regs, "dest format (not G2D_8888)", 0x1u, cfg0);
    if (cfg0 & 0xFF7F0000u)                    /* TILED[16]/SRGB[17]/SWAP fields;
                                                  STRIDESIGN[23] belongs to the stride */
        Halt(regs, "dest tiled/swapped/srgb (not modeled)", 0x1u, cfg0);
    if (regs[0x0] == 0u)                       /* null dest bind */
        Halt(regs, "dest BASE0 null bind", 0x0u, 0);
    Gpu2dFillTarget t{};
    t.dest_pa   = regs[0x0];
    t.stride_dw = imx51_g2d_regfile::StrideWords(cfg0);
    /* sync_2 libOpenVG.dll 0x41C5B468 tile loop: VGV1_SCISSORX/Y (0x24/0x25) hold the
       tile clamped in a grid anchored at 0, VGV1_TILEOFS (0x22) that tile's grid origin
       plus the path-bbox sub-tile remainder, and G2D_SCISSORX/Y (0x8/0x9) the device
       scissor - so device = grid + (TILEOFS - VGV1 near edge). */
    const uint32_t gsx = regs[0x8], gsy = regs[0x9];
    const uint32_t bsx = regs[0x24], bsy = regs[0x25];
    const int32_t v_l = static_cast<int32_t>(bsx & 0x7FFu);
    const int32_t v_t = static_cast<int32_t>(bsy & 0x7FFu);
    const int32_t ox = static_cast<int32_t>(regs[0x22] & 0xFFFu) - v_l;
    const int32_t oy = static_cast<int32_t>((regs[0x22] >> 12) & 0xFFFu) - v_t;
    t.clip_l = std::max(static_cast<int32_t>(gsx & 0x7FFu), v_l + ox);
    t.clip_r = std::min(static_cast<int32_t>((gsx >> 11) & 0x7FFu),
                        static_cast<int32_t>((bsx >> 16) & 0x7FFu) + ox);
    t.clip_t = std::max(static_cast<int32_t>(gsy & 0x7FFu), v_t + oy);
    t.clip_b = std::min(static_cast<int32_t>((gsy >> 11) & 0x7FFu),
                        static_cast<int32_t>((bsy >> 16) & 0x7FFu) + oy);
    /* The tile loops write BBOX as band/tile rect + guard margins folded into XFT, so
       (bbox+XFT)*2^exp is grid-space and takes the same ox/oy shift as the clip. */
    if (bbox_live) {
        const float ke = DeviceScale(regs);
        const float fx = static_cast<float>(ox), fy = static_cast<float>(oy);
        if ((RegF(regs, 0x5A) + RegF(regs, 0x54)) * ke + fx > static_cast<float>(t.clip_l) + 0.5f ||
            (RegF(regs, 0x5C) + RegF(regs, 0x54)) * ke + fx < static_cast<float>(t.clip_r) - 0.5f ||
            (RegF(regs, 0x5B) + RegF(regs, 0x55)) * ke + fy > static_cast<float>(t.clip_t) + 0.5f ||
            (RegF(regs, 0x5D) + RegF(regs, 0x55)) * ke + fy < static_cast<float>(t.clip_b) - 0.5f)
            Halt(regs, "VGV2 BBOX binds tighter than the scissor clip (not modeled)",
                 0x5Au, regs[0x5A]);
    }
    t.argb        = regs[0xFF];                /* G2D_COLOR, premultiplied ARGB8888 */
    t.even_odd    = (regs[0x27] & 1u) != 0u;   /* VGV1_CFG1.WINDRULE */
    t.blend       = (bcfg & (1u << 5)) != 0u;
    t.oo_alpha    = (bcfg & (1u << 6)) != 0u;
    t.premult_dst = (regs[0xC] & 0x4000u) != 0u;  /* ALPHABLEND.PREMULTIPLYDST */
    t.prog_a      = regs[0x14];                /* G2D_BLEND_A0 */
    t.prog_c      = regs[0x18];                /* G2D_BLEND_C0 */
    /* GRADW gradient paint: per-pixel SOURCE = the fmt7 ramp texel at the (OUTX,OUTY)
       the ISA program (INST0..INST(INSTRUCTIONS)) computes from CONST0-C11. */
    Gpu2dGradwPaint pg{};
    if (gradw_grad) {
        pg.texbase     = regs[0xD3];
        pg.texw        = static_cast<int32_t>(regs[0xD2] & 0x7FFu);
        pg.texh        = static_cast<int32_t>((regs[0xD2] >> 11) & 0x7FFu);
        pg.tstride     = (regs[0xD1] & 0xFFFu) + 1u;
        pg.bilinear    = (regs[0xD1] & (1u << 21)) != 0u;  /* TEXCFG.BILIN */
        pg.premultiply = (regs[0xD1] & (1u << 23)) != 0u;  /* TEXCFG.PREMULTIPLY */
        pg.wrap_u      = ((regs[0xD1] >> 17) & 0x3u) == 1u;  /* TEXCFG.WRAPU: REPEAT */
        pg.wrap_v      = ((regs[0xD1] >> 19) & 0x3u) == 1u;  /* TEXCFG.WRAPV: REPEAT */
        pg.ninst = (regs[0xD0] & 7u) + 1u;                 /* GRADIENT.INSTRUCTIONS[2:0] + 1 (program 1) */
        for (uint32_t i = 0; i < pg.ninst && i < 8u; ++i) pg.inst[i] = regs[0xE0u + i];
        for (uint32_t i = 0; i < 12u; ++i) pg.cnst[i] = UnpackGradwConst(regs[0xC0u + i]);
        t.paint = &pg;
    }
    if (!stroke) { rast.Flush(t); return; }
    /* VGV2_THINRADIUS: the stroke builder sub_41C5B1B8/setup sub_41C63970 never
       write it (only RADIUS/MITER/ARC/ACCURACY), so it stays 0; a non-zero value
       is a thin-stroke min-width clamp the stroker does not model. */
    if (regs[0x61] != 0u)
        Halt(regs, "VGV2 thin-stroke THINRADIUS clamp (not modeled)", 0x61u, regs[0x61]);
    /* Stroke: RADIUS (0x65) half-width + the XF affine + 2^EXPONENTADD + CAP/JOIN
       dilate the centerline (stroke builder sub_41C5B1B8). */
    emu_.Get<Imx51Gpu2dStroker>().Stroke(t, RegF(regs, 0x65), RegF(regs, kXf), RegF(regs, kXf + 2u),
                RegF(regs, kXf + 1u), RegF(regs, kXf + 3u), DeviceScale(regs),
                (regs[kMode] >> 4) & 3u, (regs[kMode] >> 6) & 3u, RegF(regs, kMiter));
}
