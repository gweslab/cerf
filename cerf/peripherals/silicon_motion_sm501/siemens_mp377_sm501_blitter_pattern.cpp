#define NOMINMAX

#include "siemens_mp377_sm501_blitter.h"
#include "siemens_mp377_sm501_fb.h"
#include "siemens_mp377_sm501_internal.h"
#include "siemens_mp377_sm501_rop.h"

#include <algorithm>
#include <cstdint>

namespace siemens_mp377 {

void SiemensMp377Sm501Blitter::PatternFillRect16(const SiemensMp377Sm501Blitter::State2d& st) {
    auto& fb = emu_.Get<SiemensMp377Sm501Fb>();
    uint8_t* vram = fb.MutableVramFor2d();
    if (!vram) return;
    SiemensMp377Sm501Blitter::State2d adjusted = st;
    /* SM501 Databook v1.02 section 4, 2D Control bit 27. */
    if (adjusted.backwards) {
        if (adjusted.width != 0u && adjusted.dst_x + 1u >= adjusted.width)
            adjusted.dst_x -= adjusted.width - 1u;
        if (adjusted.height != 0u && adjusted.dst_y + 1u >= adjusted.height)
            adjusted.dst_y -= adjusted.height - 1u;
    }
    const SiemensMp377Sm501Blitter::SurfaceState& dst = adjusted.dst_surface;
    const uint32_t surface_w = SurfaceWidthPixels16(dst);
    const uint32_t surface_h = SurfaceHeightRows(dst);
    if (surface_w == 0 || surface_h == 0) return;
    if (adjusted.dst_x >= surface_w || adjusted.dst_y >= surface_h) return;
    const uint32_t width = std::min(adjusted.width, surface_w - adjusted.dst_x);
    const uint32_t height = std::min(adjusted.height, surface_h - adjusted.dst_y);
    if (width == 0 || height == 0) return;
    const uint32_t stride = dst.pitch_bytes ? dst.pitch_bytes : st.dst_pitch * 2u;
    if (stride == 0) return;
    for (uint32_t y = 0; y < height; ++y) {
        const uint32_t row = dst.base + (adjusted.dst_y + y) * stride + adjusted.dst_x * 2u;
        if (row >= kSm501FbBytes) break;
        const uint32_t row_bytes = std::min(width * 2u, kSm501FbBytes - row);
        for (uint32_t x = 0; x + 1u < row_bytes; x += 2u) {
            const uint32_t px = x >> 1;
            if (!DestinationPixelEnabled(adjusted, adjusted.dst_x + px, adjusted.dst_y + y)) continue;
            const uint16_t color = PatternPixel565(adjusted, px, y);
            Sm501RasterOpPixel16(vram + row + x, st.control, color, color);
        }
        fb.Note2dWrite(row, row_bytes);
    }
}

}  // namespace siemens_mp377
