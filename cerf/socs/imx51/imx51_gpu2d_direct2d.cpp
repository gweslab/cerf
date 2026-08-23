#define NOMINMAX
#include "imx51_gpu2d_direct2d.h"

#include "../../core/cerf_emulator.h"
#include "../../core/log.h"
#include "../../boards/board_context.h"
#include "../../cpu/emulated_memory.h"
#include "imx51_gpu2d_rasterizer.h"
#include "imx51_gpu2d_regfile.h"

namespace {

constexpr uint32_t kInput = 0x0Fu;   /* ADDR_G2D_INPUT */
constexpr uint32_t kXy    = 0xF0u;   /* ADDR_G2D_XY: Y[11:0]/X[27:16] signed, vgregs_z160.h:857 */
constexpr uint32_t kWh    = 0xF1u;   /* ADDR_G2D_WIDTHHEIGHT: HEIGHT[11:0]/WIDTH[27:16], vgregs_z160.h:850 */
constexpr uint32_t kColor = 0xFFu;   /* ADDR_G2D_COLOR */
/* G2D_CFG0/1.FORMAT[15:12] surface formats (vgenums_z160.h:156-171). */
constexpr uint32_t kG2d0565 = 6u;    /* G2D_0565: 16bpp RGB565 */
constexpr uint32_t kG2d8888 = 7u;    /* G2D_8888: 32bpp ARGB */

}  /* namespace */

REGISTER_SERVICE(Imx51Gpu2dDirect2d);

bool Imx51Gpu2dDirect2d::ShouldRegister() {
    auto* bd = emu_.TryGet<BoardContext>();
    return bd && bd->GetSoc() == SocFamily::iMX51;
}

void Imx51Gpu2dDirect2d::Halt(const uint32_t (&regs)[0x100], const char* why,
                              uint32_t addr, uint32_t data) const {
    LOG(Caution, "[GPU2D-D2D] %s at 0x%08X (value 0x%08X)\n", why, addr, data);
    (void)regs;
    CerfFatalExit(CERF_FATAL_RUNTIME_ERROR);
}

/* Blender gated off above -> ALPHABLEND is inert; admit its two ambient defaults
   OBS_ENABLE[8] (surface-init) and PREMULTIPLYDST[14] (copy emitter sub_41C6C448
   sets it blend-off), FATAL deliberate modulation. ROP 0x404 = surface-init
   default (sub_41C61DB4), admitted as the ops' undecoded constant. */
void Imx51Gpu2dDirect2d::CheckCommonGates(const uint32_t (&regs)[0x100]) const {
    if (regs[0x11] & (1u << 5))  /* G2D_BLENDERCFG.ENABLE */
        Halt(regs, "direct-2D op with blender enabled (not modeled)", 0x11u, regs[0x11]);
    if (regs[0xC] & ~0x4100u)  /* ALPHABLEND OBS_ENABLE[8] | PREMULTIPLYDST[14], both inert */
        Halt(regs, "direct-2D op ALPHABLEND modulation (not modeled)", 0xCu, regs[0xC]);
    if (regs[0xD] != 0x404u)
        Halt(regs, "direct-2D op ROP (not modeled)", 0xDu, regs[0xD]);
    if (regs[0xD0] & 0xC0u)  /* G2D_GRADIENT.ENABLE|ENABLE2 */
        Halt(regs, "direct-2D op gradient paint (not modeled)", 0xD0u, regs[0xD0]);
    if (regs[0x10] != 0xFFFFFFu)  /* G2D_MASK identity wrap */
        Halt(regs, "direct-2D op MASK wrap (not modeled)", 0x10u, regs[0x10]);
    const uint32_t cfg0 = regs[0x1];
    if (cfg0 & 0xFF7F0000u)  /* TILED[16]/SRGB[17]/SWAP fields: linear, no swap - per-op
                                FORMAT decode; STRIDESIGN[23] is part of the stride */
        Halt(regs, "direct-2D op dest swap/tile/srgb (not modeled)", 0x1u, cfg0);
    if (regs[0x0] == 0u)
        Halt(regs, "direct-2D op dest BASE0 null bind", 0x0u, 0);
}

/* Direct-2D solid rect fill (fast path sub_41C6C6DC -> emitter sub_41C620DC:
   SCISSOR+XY+WIDTHHEIGHT+COLOR under INPUT=1, blender force-disabled). */
void Imx51Gpu2dDirect2d::Fill(const uint32_t (&regs)[0x100]) {
    CheckCommonGates(regs);
    if (regs[0xE] != 0u && regs[0xE] != 0xF000u)  /* G2D_CONFIG: ARGBMASK-all fill only */
        Halt(regs, "direct-2D fill CONFIG mode (not modeled)", 0xEu, regs[0xE]);
    const uint32_t cfg0 = regs[0x1];
    const uint32_t fmt = (cfg0 >> 12) & 0xFu;
    if (fmt != kG2d8888 && fmt != kG2d0565)
        Halt(regs, "direct-2D fill dest format (not G2D_8888/G2D_0565)", 0x1u, cfg0);
    const uint32_t xy = regs[kXy], wh = regs[kWh];
    Gpu2dFillTarget t{};
    t.dest_pa   = regs[0x0];
    t.stride_dw = imx51_g2d_regfile::StrideWords(cfg0);
    t.dest_565  = (fmt == kG2d0565);
    /* G2D scissor only: the emitter programs it to the rect itself; the VGV1
       band scissor belongs to the VG rasterizer path and may be stale here. */
    const uint32_t gsx = regs[0x8], gsy = regs[0x9];
    t.clip_l = static_cast<int32_t>(gsx & 0x7FFu);
    t.clip_r = static_cast<int32_t>((gsx >> 11) & 0x7FFu);
    t.clip_t = static_cast<int32_t>(gsy & 0x7FFu);
    t.clip_b = static_cast<int32_t>((gsy >> 11) & 0x7FFu);
    /* The emitter writes COLOR R/B-swapped in direct mode (sub_41C620DC
       BYTE2|byte0<<16|bytes-1,3-kept); un-swap so memory receives the same
       ARGB order the VG fill path writes. */
    const uint32_t c = regs[kColor];
    t.argb = (c & 0xFF00FF00u) | ((c >> 16) & 0xFFu) | ((c & 0xFFu) << 16);
    emu_.Get<Imx51Gpu2dRasterizer>().FillRect(
        t, static_cast<int32_t>(xy << 4) >> 20, static_cast<int32_t>(xy << 20) >> 20,
        static_cast<int32_t>(wh << 4) >> 20, static_cast<int32_t>(wh << 20) >> 20);
}

/* SCOORD1 source->dest copy (emitter sub_41C6C448, the EGL swap-buffer preserve
   copy). Both CFG0/CFG1 = STRIDE|0x7000 (FORMAT 7, all swap fields 0), so it is a
   byte-identical fmt7 copy - CopyRect must NOT permute channels despite CFG having
   SWAPRB/SWAPBYTES fields. */
void Imx51Gpu2dDirect2d::Copy(const uint32_t (&regs)[0x100], uint32_t sxy) {
    if (regs[kInput] != 2u)  /* G2D_INPUT SCOORD1 (sub_41C6C448 sets 2) */
        Halt(regs, "SXY copy under unmodeled G2D_INPUT", kInput, regs[kInput]);
    if (regs[0xE] != 2u)  /* G2D_CONFIG SRC1-only: DST[0]=0/SRC1[1]=1, no SRC2/SRC3/
                             colorkey/rotate/argbmask (vgregs_z160.h:2636-2655) */
        Halt(regs, "SXY copy CONFIG mode (not SRC1-only)", 0xEu, regs[0xE]);
    CheckCommonGates(regs);
    const uint32_t cfg0 = regs[0x1], cfg1 = regs[0x3];
    if (((cfg0 >> 12) & 0xFu) != kG2d8888)  /* copy dest G2D_8888 only (565 dest copy not modeled) */
        Halt(regs, "SXY copy dest format (not G2D_8888)", 0x1u, cfg0);
    if (((cfg1 >> 12) & 0xFu) != 7u || (cfg1 & 0xFF7F0000u))  /* src G2D_8888, no swap/tile/srgb */
        Halt(regs, "SXY copy source format (not linear G2D_8888)", 0x3u, cfg1);
    if (regs[0x2] == 0u)
        Halt(regs, "SXY copy source BASE1 null bind", 0x2u, 0);
    const uint32_t xy = regs[kXy], wh = regs[kWh];
    Gpu2dCopySpec c{};
    c.dst_pa        = regs[0x0];
    c.dst_stride_dw = imx51_g2d_regfile::StrideWords(cfg0);
    c.src_pa        = regs[0x2];
    c.src_stride_dw = imx51_g2d_regfile::StrideWords(cfg1);
    const uint32_t gsx = regs[0x8], gsy = regs[0x9];  /* dest G2D scissor (inclusive) */
    c.clip_l = static_cast<int32_t>(gsx & 0x7FFu);
    c.clip_r = static_cast<int32_t>((gsx >> 11) & 0x7FFu);
    c.clip_t = static_cast<int32_t>(gsy & 0x7FFu);
    c.clip_b = static_cast<int32_t>((gsy >> 11) & 0x7FFu);
    c.dst_x = static_cast<int32_t>(xy << 4) >> 20;   /* G2D_XY.X[27:16] signed 12 */
    c.dst_y = static_cast<int32_t>(xy << 20) >> 20;  /* G2D_XY.Y[11:0] signed 12 */
    c.w     = static_cast<int32_t>(wh << 4) >> 20;   /* G2D_WIDTHHEIGHT.WIDTH[27:16] signed 12 */
    c.h     = static_cast<int32_t>(wh << 20) >> 20;  /* G2D_WIDTHHEIGHT.HEIGHT[11:0] signed 12 */
    c.src_x = static_cast<int32_t>((sxy >> 16) & 0x7FFu);  /* G2D_SXY.X[26:16] unsigned 11 */
    c.src_y = static_cast<int32_t>(sxy & 0x7FFu);          /* G2D_SXY.Y[10:0] unsigned 11 */
    CopyRect(c);
}

/* Both CFG0 (dest) and CFG1 (src) are STRIDE|0x7000 (FORMAT 7, all swap fields 0),
   so no channel permute or format convert occurs; move each 32bpp pixel verbatim,
   dest-clipped to the G2D scissor. gpuaddr==physical (GPU MMU disabled). */
void Imx51Gpu2dDirect2d::CopyRect(const Gpu2dCopySpec& c) {
    auto& mem = emu_.Get<EmulatedMemory>();
    for (int32_t row = 0; row < c.h; ++row) {
        const int32_t dy = c.dst_y + row;
        if (dy < c.clip_t || dy > c.clip_b) continue;
        const int32_t sy = c.src_y + row;
        for (int32_t col = 0; col < c.w; ++col) {
            const int32_t dx = c.dst_x + col;
            if (dx < c.clip_l || dx > c.clip_r) continue;
            const int32_t sx = c.src_x + col;
            const uint32_t spa = c.src_pa + static_cast<uint32_t>((sy * c.src_stride_dw
                                                                   + sx) * 4);
            const uint8_t* shp = mem.TryTranslate(spa);
            if (!shp) {
                LOG(Caution, "[GPU2D-D2D] copy source pixel unbacked pa=0x%08X (x=%d y=%d)\n",
                    spa, sx, sy);
                CerfFatalExit(CERF_FATAL_RUNTIME_ERROR);
            }
            const uint32_t dpa = c.dst_pa + static_cast<uint32_t>((dy * c.dst_stride_dw
                                                                   + dx) * 4);
            uint8_t* dhp = mem.TryTranslateWrite(dpa);
            if (!dhp) {
                LOG(Caution, "[GPU2D-D2D] copy dest pixel unbacked pa=0x%08X (x=%d y=%d)\n",
                    dpa, dx, dy);
                CerfFatalExit(CERF_FATAL_RUNTIME_ERROR);
            }
            *reinterpret_cast<uint32_t*>(dhp) = *reinterpret_cast<const uint32_t*>(shp);
        }
    }
}
