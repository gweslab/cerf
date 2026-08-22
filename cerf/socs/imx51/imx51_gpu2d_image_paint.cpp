#define NOMINMAX
#include "imx51_gpu2d_image_paint.h"

#include "../../core/cerf_emulator.h"
#include "../../core/log.h"
#include "../../boards/board_context.h"
#include "../../cpu/emulated_memory.h"
#include "imx51_gpu2d_blend.h"
#include "imx51_gpu2d_regfile.h"
#include "imx51_gpu2d_gradw_sampler.h"

#include <algorithm>
#include <cmath>

namespace {
using namespace imx51_g2d_blend;
using namespace imx51_g2d_regfile;

constexpr uint32_t kBase0 = 0x00u, kCfg0 = 0x01u, kScisX = 0x08u, kScisY = 0x09u;
constexpr uint32_t kAlphaBlend = 0x0Cu, kRop = 0x0Du, kConfig = 0x0Eu, kInput = 0x0Fu;
constexpr uint32_t kMask = 0x10u, kBcfg = 0x11u;
constexpr uint32_t kBlendA0 = 0x14u, kBlendC0 = 0x18u;
constexpr uint32_t kConst0 = 0xC0u;                       /* CONST0-5 = 0xC0-0xC5 (affine coeffs) */
constexpr uint32_t kGradient = 0xD0u, kTexCfg = 0xD1u, kTexSize = 0xD2u, kTexBase = 0xD3u;
constexpr uint32_t kInst0 = 0xE0u, kInst1 = 0xE1u, kXy = 0xF0u, kWh = 0xF1u, kColor = 0xFFu;

/* The one captured SRC_OVER image-paint program (VG blend mode 8193); every other
   value born-FATAL. GRADIENT 0x188 = ENABLE2|SEL|INSTRUCTIONS2=1 (a 2-instruction
   texture fetch); INST0/1 = the S/T affine MAC (S = px*C0+py*C1+C2, T likewise). */
constexpr uint32_t kGradientImg = 0x188u;
constexpr uint32_t kInst0Affine = 0x10080632u, kInst1Affine = 0x12098695u;
constexpr uint32_t kBcfgVal = 0x69u;                      /* ENABLE|OOALPHA|PASSES=1|ALPHAPASSES=1 */
constexpr uint32_t kProgA0 = 0x065900E0u, kProgC0 = 0x065904E0u;  /* setup: TEMP1=SRC*IMG, TEMP2=SRC.a*IMG */
constexpr uint32_t kProgA1 = 0x0A85A004u, kProgC1 = 0x0C85A004u;  /* combine: TEMP0=TEMP1+DEST*(1-TEMP2) */
/* libOpenVG.dll sub_41C6338C (VA 0x41C6338C), captured live from a Ford SYNC 2
   boot: second legal image-paint program (VG_BLEND_SRC). */
constexpr uint32_t kProgA0Src = 0x00190320u, kProgC0Src = 0x00190020u;
constexpr uint32_t kProgA1Src = 0x00852004u, kProgC1Src = 0x00852004u;
/* TEXCFG minus STRIDE: FORMAT 7 | PREMULTIPLY[23] | TEX2D[28], everything else 0
   (TILED/WRAP/BILIN/SRGB/SWAP*). A BILIN or swapped or non-premult texture would
   sample wrong, so the whole upper word is gated. */
constexpr uint32_t kTexCfgUpper = 0x10807000u;

}  // namespace

REGISTER_SERVICE(Imx51Gpu2dImagePaint);

bool Imx51Gpu2dImagePaint::ShouldRegister() {
    auto* bd = emu_.TryGet<BoardContext>();
    return bd && bd->GetSoc() == SocFamily::iMX51;
}

void Imx51Gpu2dImagePaint::Halt(const uint32_t (&regs)[0x100], const char* why,
                                uint32_t addr, uint32_t data) const {
    LOG(Caution, "[GPU2D-IMGPAINT] %s at 0x%08X (value 0x%08X)\n", why, addr, data);
    (void)regs;
    CerfFatalExit(CERF_FATAL_RUNTIME_ERROR);
}

void Imx51Gpu2dImagePaint::CheckGates(const uint32_t (&regs)[0x100]) const {
    if (regs[kInput] != 0x09u)
        Halt(regs, "INPUT (not COLOR|COPYCOORD)", kInput, regs[kInput]);
    if ((regs[kGradient] & ~7u) != kGradientImg)  /* low 3 bits = INSTRUCTIONS (program 1, ENABLE[6] clear) */
        Halt(regs, "GRADIENT program (not the 2-instruction image fetch)", kGradient, regs[kGradient]);
    if (regs[kInst0] != kInst0Affine || regs[kInst1] != kInst1Affine)
        Halt(regs, "GRADW INST (not the S/T affine MAC)", kInst0, regs[kInst0]);
    if ((regs[kTexCfg] & 0xFFFFF000u) != kTexCfgUpper)
        Halt(regs, "texture config (not fmt7 nearest premult, no swap/wrap)", kTexCfg, regs[kTexCfg]);
    if ((regs[kTexSize] & 0x7FFu) == 0u || ((regs[kTexSize] >> 11) & 0x7FFu) == 0u)
        Halt(regs, "texture zero size", kTexSize, regs[kTexSize]);
    if (regs[kConfig] != 0x01u)  /* DST[0]=1 only; SRC1=0 disables the second texture */
        Halt(regs, "CONFIG (not DST-only, SRC1 disabled)", kConfig, regs[kConfig]);
    if (regs[kBcfg] != kBcfgVal)
        Halt(regs, "BLENDERCFG (not the SRC_OVER multi-pass)", kBcfg, regs[kBcfg]);
    const bool isSrcOver = regs[kBlendC0] == kProgC0 && regs[kBlendA0] == kProgA0 &&
        regs[kBlendC0 + 1u] == kProgC1 && regs[kBlendA0 + 1u] == kProgA1;
    const bool isSrcCopy = regs[kBlendC0] == kProgC0Src && regs[kBlendA0] == kProgA0Src &&
        regs[kBlendC0 + 1u] == kProgC1Src && regs[kBlendA0 + 1u] == kProgA1Src;
    if (!isSrcOver && !isSrcCopy)
        Halt(regs, "blend program (not a captured SRC_OVER/SRC_SRC)", kBlendC0, regs[kBlendC0]);
    if (regs[kAlphaBlend] != 0x4100u)  /* OBS_ENABLE[8] | PREMULTIPLYDST[14] */
        Halt(regs, "ALPHABLEND (not OBS_ENABLE|PREMULTIPLYDST)", kAlphaBlend, regs[kAlphaBlend]);
    if (regs[kRop] != 0x404u)
        Halt(regs, "ROP", kRop, regs[kRop]);
    if (regs[kMask] != 0xFFFFFFu)
        Halt(regs, "MASK wrap", kMask, regs[kMask]);
    const uint32_t cfg0 = regs[kCfg0];
    if (((cfg0 >> 12) & 0xFu) != 7u || (cfg0 >> 16))
        Halt(regs, "dest format (not linear G2D_8888)", kCfg0, cfg0);
    if (regs[kBase0] == 0u)
        Halt(regs, "dest BASE0 null bind", kBase0, 0);
    if (regs[kTexBase] == 0u)
        Halt(regs, "texture TEXBASE null bind", kTexBase, 0);
}

uint32_t Imx51Gpu2dImagePaint::BlendMultiPass(const uint32_t (&regs)[0x100],
                                              uint32_t src, uint32_t dst) const {
    /* ALPHABLEND.PREMULTIPLYDST (gated set): premultiply the straight-alpha dest. */
    const uint32_t dstop = PremultArgb(dst);
    const uint32_t image = 0xFFFFFFFFu;  /* SRC1=0: second texture disabled -> identity */
    uint32_t temp[3] = {0u, 0u, 0u};

    auto operand = [&](uint32_t prog, uint32_t i, uint32_t shift) -> uint32_t {
        const uint32_t sh = Ar(prog, i) ? 24u : shift;
        uint32_t v;
        switch (Src(prog, i)) {
            case kSrcZero:   v = 0u; break;
            case kSrcSource: v = (src >> sh) & 0xFFu; break;
            case kSrcDest:   v = (dstop >> sh) & 0xFFu; break;
            case kSrcImage:  v = (image >> sh) & 0xFFu; break;
            case kSrcTemp0:  v = (temp[0] >> sh) & 0xFFu; break;
            case kSrcTemp1:  v = (temp[1] >> sh) & 0xFFu; break;
            default:         v = (temp[2] >> sh) & 0xFFu; break;  /* TEMP2 (SRC 7 gated out) */
        }
        return Inv(prog, i) ? 255u - v : v;
    };
    auto run = [&](uint32_t prog, uint32_t shift) {
        const uint32_t p1 = Mul(operand(prog, 0, shift), operand(prog, 1, shift));
        const uint32_t p2 = Mul(operand(prog, 2, shift), operand(prog, 3, shift));
        auto put = [&](uint32_t d, uint32_t val) {
            if (d == kDstIgnore) return;
            temp[d - 1u] = (temp[d - 1u] & ~(0xFFu << shift)) | (std::min(val, 255u) << shift);
        };
        put(Dst(prog, 0), p1 + p2);  /* DST_A <- P1+P2 */
        put(Dst(prog, 1), p1);       /* DST_B <- P1 */
        put(Dst(prog, 2), p2);       /* DST_C <- P2 */
    };

    const uint32_t passes = (regs[kBcfg] & 7u) + 1u;           /* PASSES[2:0] + 1 color passes */
    const uint32_t apasses = ((regs[kBcfg] >> 3) & 3u) + 1u;   /* ALPHAPASSES[4:3] + 1 alpha passes */
    for (uint32_t p = 0; p < passes; ++p) {
        run(regs[kBlendC0 + p], 16u);
        run(regs[kBlendC0 + p], 8u);
        run(regs[kBlendC0 + p], 0u);
    }
    for (uint32_t p = 0; p < apasses; ++p)
        run(regs[kBlendA0 + p], 24u);

    uint32_t out = temp[0];  /* output pixel = TEMP0 */
    if (regs[kBcfg] & (1u << 6)) {  /* OOALPHA: un-premultiply back to straight-alpha */
        const uint32_t a = out >> 24;
        if (a == 0u) {
            out = 0u;
        } else if (a != 255u) {
            out = (a << 24) | (UnpremultChannel((out >> 16) & 0xFFu, a) << 16)
                | (UnpremultChannel((out >> 8) & 0xFFu, a) << 8) | UnpremultChannel(out & 0xFFu, a);
        }
    }
    return out;
}

void Imx51Gpu2dImagePaint::Composite(const uint32_t (&regs)[0x100]) {
    CheckGates(regs);
    const uint32_t xy = regs[kXy], wh = regs[kWh];
    const int32_t x0 = static_cast<int32_t>(xy << 4) >> 20;   /* G2D_XY.X[27:16] signed 12 */
    const int32_t y0 = static_cast<int32_t>(xy << 20) >> 20;  /* G2D_XY.Y[11:0] signed 12 */
    const int32_t w  = static_cast<int32_t>(wh << 4) >> 20;   /* WIDTH[27:16] signed 12 */
    const int32_t h  = static_cast<int32_t>(wh << 20) >> 20;  /* HEIGHT[11:0] signed 12 */
    if (w <= 0 || h <= 0) return;
    const uint32_t stride = (regs[kCfg0] & 0xFFFu) + 1u;
    const uint32_t gsx = regs[kScisX], gsy = regs[kScisY];   /* LEFT[10:0]/RIGHT[21:11] inclusive */
    const int32_t cl = static_cast<int32_t>(gsx & 0x7FFu);
    const int32_t cr = static_cast<int32_t>((gsx >> 11) & 0x7FFu);
    const int32_t ct = static_cast<int32_t>(gsy & 0x7FFu);
    const int32_t cb = static_cast<int32_t>((gsy >> 11) & 0x7FFu);
    Gpu2dGradwPaint pg{};
    pg.texbase = regs[kTexBase];
    pg.texw    = static_cast<int32_t>(regs[kTexSize] & 0x7FFu);         /* WIDTH[10:0] */
    pg.texh    = static_cast<int32_t>((regs[kTexSize] >> 11) & 0x7FFu); /* HEIGHT[21:11] */
    pg.tstride = (regs[kTexCfg] & 0xFFFu) + 1u;                         /* TEXCFG.STRIDE + 1 */
    pg.bilinear    = (regs[kTexCfg] & (1u << 21)) != 0u;               /* TEXCFG.BILIN (gated 0) */
    pg.premultiply = (regs[kTexCfg] & (1u << 23)) != 0u;               /* TEXCFG.PREMULTIPLY (gated 1) */
    pg.ninst = ((regs[kGradient] >> 3) & 7u) + 1u;                     /* GRADIENT.INSTRUCTIONS2[5:3] + 1 (program 2) */
    for (uint32_t i = 0; i < pg.ninst && i < 8u; ++i) pg.inst[i] = regs[kInst0 + i];
    for (uint32_t i = 0; i < 12u; ++i) pg.cnst[i] = UnpackGradwConst(regs[kConst0 + i]);
    auto& samp = emu_.Get<Imx51Gpu2dGradwSampler>();
    auto& mem = emu_.Get<EmulatedMemory>();
    for (int32_t row = 0; row < h; ++row) {
        const int32_t py = y0 + row;
        if (py < ct || py > cb) continue;
        for (int32_t col = 0; col < w; ++col) {
            const int32_t px = x0 + col;
            if (px < cl || px > cr) continue;
            /* STENCIL image-paint SOURCE = GRADW glyph texel x COLOR (both premult). */
            const uint32_t src = MulArgb(samp.Sample(pg, px, py), regs[kColor]);
            const uint32_t dpa = regs[kBase0] + (static_cast<uint32_t>(py) * stride
                                                 + static_cast<uint32_t>(px)) * 4u;
            uint8_t* dhp = mem.TryTranslateWrite(dpa);
            if (!dhp) {
                LOG(Caution, "[GPU2D-IMGPAINT] dest unbacked pa=0x%08X (x=%d y=%d)\n", dpa, px, py);
                CerfFatalExit(CERF_FATAL_RUNTIME_ERROR);
            }
            uint32_t* dp = reinterpret_cast<uint32_t*>(dhp);
            *dp = BlendMultiPass(regs, src, *dp);
        }
    }
}
