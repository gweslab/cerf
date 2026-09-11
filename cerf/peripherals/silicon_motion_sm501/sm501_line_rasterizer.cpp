#include "sm501_line_rasterizer.h"
#include "siemens_mp377_sm501_rop.h"

#include <algorithm>
#include <limits>

namespace siemens_mp377 {

Sm501LineDirtyRange RasterizeSm501Line(const Sm501LineState& state) {
    /* SM501 Databook v1.02 section 4; siemens_mp377_v1040
       ddi_vgx.dll 0x02996B4C. */
    const uint32_t k1 = (state.source >> 16u) & 0x3FFFu;
    const uint32_t k2_raw = state.source & 0x3FFFu;
    const int32_t k2 = k2_raw >= 0x2000u
                           ? static_cast<int32_t>(k2_raw) - 0x4000
                           : static_cast<int32_t>(k2_raw);
    int32_t error = static_cast<int16_t>(state.dimension & 0xFFFFu);
    const uint32_t vector_length = (state.dimension >> 16u) & 0x1FFFu;
    if (vector_length == 0u) return {};

    const int32_t major_delta = static_cast<int32_t>(vector_length - 1u);
    const int32_t minor_delta = static_cast<int32_t>(k1 / 2u);
    const bool y_major = (state.control & 0x04000000u) != 0u;
    const int32_t x_step = (state.control & 0x02000000u) ? -1 : 1;
    const int32_t y_step = (state.control & 0x01000000u) ? -1 : 1;
    const int32_t dx = y_major ? minor_delta : major_delta;
    const int32_t dy = y_major ? major_delta : minor_delta;
    int32_t x = static_cast<int32_t>(state.destination_x) - x_step * dx;
    int32_t y = static_cast<int32_t>(state.destination_y) - y_step * dy;
    const uint32_t pixel_count = vector_length - ((state.control & 0x00200000u) ? 0u : 1u);
    uint32_t first_dirty = std::numeric_limits<uint32_t>::max();
    uint32_t last_dirty = 0u;

    for (uint32_t i = 0; i < pixel_count; ++i) {
        if (x >= 0 && y >= 0 && static_cast<uint32_t>(x) < state.surface_width &&
            static_cast<uint32_t>(y) < state.surface_height) {
            /* siemens_mp377_v1040 ddi_vgx.dll sub_2996AB8; Win32 RECT. */
            const bool inside_clip = static_cast<uint32_t>(x) >= state.clip_left &&
                                     static_cast<uint32_t>(x) < state.clip_right &&
                                     static_cast<uint32_t>(y) >= state.clip_top &&
                                     static_cast<uint32_t>(y) < state.clip_bottom;
            const bool clipped = state.clip_enabled && (state.clip_excludes_inside ? inside_clip : !inside_clip);
            if (!clipped) {
                const uint32_t off = state.surface_base + static_cast<uint32_t>(y) * state.surface_pitch +
                                     static_cast<uint32_t>(x) * 2u;
                if (off + 1u < state.vram_size) {
                    const uint16_t d = static_cast<uint16_t>(state.vram[off] | (state.vram[off + 1u] << 8u));
                    const uint16_t out =
                        Sm501ApplyRasterOp16(state.control, state.foreground, d, state.foreground);
                    state.vram[off] = static_cast<uint8_t>(out);
                    state.vram[off + 1u] = static_cast<uint8_t>(out >> 8u);
                    first_dirty = std::min(first_dirty, off);
                    last_dirty = std::max(last_dirty, off + 2u);
                }
            }
        }
        if (y_major) y += y_step; else x += x_step;
        if (error >= 0) {
            if (y_major) x += x_step; else y += y_step;
            error += k2;
        } else {
            error += static_cast<int32_t>(k1);
        }
    }
    if (first_dirty == std::numeric_limits<uint32_t>::max()) return {};
    return {first_dirty, last_dirty - first_dirty};
}

} // namespace siemens_mp377
