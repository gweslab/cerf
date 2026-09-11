#pragma once

#include <cstddef>
#include <cstdint>

namespace siemens_mp377 {

struct Sm501LineState {
    uint8_t* vram;
    size_t vram_size;
    uint32_t surface_base;
    uint32_t surface_pitch;
    uint32_t surface_width;
    uint32_t surface_height;
    uint32_t destination_x;
    uint32_t destination_y;
    uint32_t source;
    uint32_t dimension;
    uint32_t control;
    uint16_t foreground;
    bool clip_enabled;
    bool clip_excludes_inside;
    uint32_t clip_left;
    uint32_t clip_top;
    uint32_t clip_right;
    uint32_t clip_bottom;
};

struct Sm501LineDirtyRange {
    uint32_t offset = 0;
    uint32_t size = 0;
};

Sm501LineDirtyRange RasterizeSm501Line(const Sm501LineState& state);

} // namespace siemens_mp377
