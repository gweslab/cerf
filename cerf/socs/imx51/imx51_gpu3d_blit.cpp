#include "imx51_gpu3d_blit.h"
#include "imx51_gpu3d_memory.h"
#include "../../lcd/lcd_pixel_expand.h"
#include "../../core/byte_order.h"
#include "../../core/cerf_emulator.h"
#include "../../core/fatal.h"
#include "../../boards/board_context.h"
#include "imx51_id.h"
#include <cstring>

REGISTER_SERVICE(Imx51Gpu3dBlit);

bool Imx51Gpu3dBlit::ShouldRegister() {
    auto* board = emu_.TryGet<BoardContext>();
    return board && board->GetSocId() == SocId::Imx51;
}

void Imx51Gpu3dBlit::HaltUnsupportedAccess(const char* op, uint32_t address, uint64_t value) const {
    emu_.Get<Fatal>().Die("GPU blit rejected %s at 0x%08X (value 0x%016llX)",
                          op, address, static_cast<unsigned long long>(value));
}

uint32_t Imx51Gpu3dBlit::BlitReg(const std::unordered_map<uint32_t, uint32_t>& registers, uint32_t idx, uint64_t pa) {
    auto it = registers.find(idx);
    if (it == registers.end())
        HaltUnsupportedAccess("blit config register not programmed", static_cast<uint32_t>(pa), idx);
    return it->second;
}
float Imx51Gpu3dBlit::AsFloat(uint32_t u) { float f; std::memcpy(&f, &u, sizeof(f)); return f; }

/* sync_2 EA5T-14D544-BA.sec, lib2d-z430.dll: 0x41A63F00;
   Mesa e97ad748 a2xx.xml: A2XX_SQ_TEX, RB_COLOR_INFO, RB_SURFACE_INFO,
   RB_COLORCONTROL, RB_COLOR_MASK, PA_CL_VTE_CNTL and PA_SC_WINDOW_SCISSOR. */
void Imx51Gpu3dBlit::Draw(uint32_t ctrl, uint64_t pa,
                          const std::unordered_map<uint32_t, uint32_t>& registers,
                          uint32_t mmu_config) {
    /* NXP a1638da9 PA_SU_SC_MODE_CNTL: the C2D shortcut must not bypass the
       draw frontend's exclusion of face-stream side effects. */
    const uint32_t face = BlitReg(registers, 0x2205u, pa);
    if (face & 0xF0000000u)
        HaltUnsupportedAccess("faceness controls", static_cast<uint32_t>(pa), face);
    if ((ctrl & 0x3Fu) != 6u ||
        ((ctrl >> 6) & 0x3u) != 2u ||
        (ctrl >> 16) != 4u)
        HaltUnsupportedAccess("DRAW_INDX not the C2D2 4-vert blit", static_cast<uint32_t>(pa), ctrl);

    const uint32_t ci = BlitReg(registers, 0x2001u, pa);
    const uint32_t dstFmt = ci & 0xFu;
    if ((dstFmt != 5u && dstFmt != 2u) || ((ci >> 9) & 0x3u) != 1u)
        HaltUnsupportedAccess("blit dest not COLORX_8_8_8_8/5_6_5 SWAP=1", static_cast<uint32_t>(pa), ci);
    const uint32_t dstBase  = ci & 0xFFFFF000u;
    const uint32_t dstBpp   = (dstFmt == 2u) ? 2u : 4u;
    const uint32_t dstPitch = BlitReg(registers, 0x2000u, pa) & 0x3FFFu;

    const uint32_t cohBase = BlitReg(registers, 0x0A2Au, pa);
    uint32_t fb = 0u;
    for (uint32_t s = 0u; s < 16u && fb == 0u; ++s) {
        auto it = registers.find(0x4801u + s * 6u);
        if (it != registers.end() && (it->second & 0xFFFFF000u) == cohBase)
            fb = 0x4800u + s * 6u;
    }
    if (fb == 0u)
        HaltUnsupportedAccess("blit source fetch const not found", static_cast<uint32_t>(pa), cohBase);
    const uint32_t sw0 = BlitReg(registers, fb + 0u, pa), sw1 = BlitReg(registers, fb + 1u, pa);
    const uint32_t sw2 = BlitReg(registers, fb + 2u, pa), sw3 = BlitReg(registers, fb + 3u, pa);
    const uint32_t srcFmt = sw1 & 0x3Fu;
    const uint32_t swizW  = (sw3 >> 10) & 0x7u;
    if ((srcFmt != 6u && srcFmt != 4u) || (sw0 >> 31) != 0u ||
        ((sw3 >> 19) & 0x3u) != 0u || ((sw3 >> 21) & 0x3u) != 0u ||
        ((sw3 >> 1) & 0x7u) != 2u || ((sw3 >> 4) & 0x7u) != 1u ||
        ((sw3 >> 7) & 0x7u) != 0u ||
        (swizW != 3u && swizW != 5u)) {
        HaltUnsupportedAccess("blit source not FMT_8888/565 POINT BGRA", static_cast<uint32_t>(pa), sw3);
    }
    const uint32_t srcBpp = (srcFmt == 4u) ? 2u : 4u;

    if (swizW == 5u && dstBpp == 4u)
        HaltUnsupportedAccess("blit SWIZ_W=ONE into 8888 dest (alpha-force not modeled)", static_cast<uint32_t>(pa), sw3);
    const uint32_t srcBase  = sw1 & 0xFFFFF000u;
    const uint32_t srcPitch = ((sw0 >> 22) & 0x1FFu) << 5;
    const uint32_t srcW     = (sw2 & 0x1FFFu) + 1u;
    const uint32_t srcH     = ((sw2 >> 13) & 0x1FFFu) + 1u;

    if (((BlitReg(registers, 0x2202u, pa) >> 5) & 0x1u) != 1u ||
        (BlitReg(registers, 0x2104u, pa) & 0xFu) != 0xFu ||
        (BlitReg(registers, 0x2206u, pa) & 0x3Fu) != 0u)
        HaltUnsupportedAccess("blit not opaque/full-mask/direct-coord", static_cast<uint32_t>(pa), ci);

    const uint32_t vhw = BlitReg(registers, 0x4048u, pa), vhh = BlitReg(registers, 0x4049u, pa);
    if (AsFloat(vhw) * 2.0f != static_cast<float>(srcW) ||
        AsFloat(vhh) * 2.0f != static_cast<float>(srcH) ||
        BlitReg(registers, 0x404Au, pa) != vhw || BlitReg(registers, 0x404Bu, pa) != vhh)
        HaltUnsupportedAccess("blit geometry not 1:1 full-screen", static_cast<uint32_t>(pa), srcW);
    for (uint32_t k = 0u; k < 4u; ++k)
        if (BlitReg(registers, 0x4098u + k, pa) != 0x3F000000u)
            HaltUnsupportedAccess("blit tex not full [0,1]", static_cast<uint32_t>(pa), 0x4098u + k);
    const uint32_t tl = BlitReg(registers, 0x2081u, pa), br = BlitReg(registers, 0x2082u, pa);
    if ((tl & 0x7FFFu) != 0u || ((tl >> 16) & 0x7FFFu) != 0u ||
        (br & 0x7FFFu) < srcW || ((br >> 16) & 0x7FFFu) < srcH)
        HaltUnsupportedAccess("blit scissor origin/clip", static_cast<uint32_t>(pa), br);

    const uint64_t sSpan = uint64_t(srcH - 1u) * srcPitch * srcBpp + uint64_t(srcW) * srcBpp;
    const uint64_t dSpan = uint64_t(srcH - 1u) * dstPitch * dstBpp + uint64_t(srcW) * dstBpp;
    const uint8_t* s0 = emu_.Get<Imx51Gpu3dMemory>().ReadSpan(srcBase, sSpan, mmu_config);
    uint8_t* d0 = emu_.Get<Imx51Gpu3dMemory>().WriteSpan(dstBase, dSpan, mmu_config);
    if (srcBpp == dstBpp) {
        for (uint32_t y = 0u; y < srcH; ++y)
            std::memmove(d0 + uint64_t(y) * dstPitch * dstBpp, s0 + uint64_t(y) * srcPitch * srcBpp, srcW * srcBpp);
    } else if (srcBpp == 4u) {
        for (uint32_t y = 0u; y < srcH; ++y) {
            const uint8_t* srow = s0 + uint64_t(y) * srcPitch * 4u;
            uint8_t* drow = d0 + uint64_t(y) * dstPitch * 2u;
            for (uint32_t x = 0u; x < srcW; ++x)
                cerf::le::Put16(drow + x * 2u,
                                lcd_pixel::PackRgb565(cerf::le::U32(srow, x * 4u)));
        }
    } else {
        HaltUnsupportedAccess("blit 565 source into 8888 dest (expand not modeled)", srcBase, dstBase);
    }
}
