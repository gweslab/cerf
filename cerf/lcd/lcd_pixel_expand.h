#pragma once

#include <cstdint>

namespace lcd_pixel {

inline uint32_t Expand4(uint32_t v) { return (v << 4) | v; }
inline uint32_t Expand5(uint32_t v) { return (v << 3) | (v >> 2); }
inline uint32_t Expand6(uint32_t v) { return (v << 2) | (v >> 4); }

inline uint32_t PackXrgb(uint32_t r, uint32_t g, uint32_t b) {
    return 0xFF000000u | (r << 16) | (g << 8) | b;
}

inline uint32_t Expand565(uint16_t px) {
    return PackXrgb(Expand5((px >> 11) & 0x1Fu), Expand6((px >> 5) & 0x3Fu), Expand5(px & 0x1Fu));
}

inline uint32_t Expand555(uint16_t px) {
    return PackXrgb(Expand5((px >> 10) & 0x1Fu), Expand5((px >> 5) & 0x1Fu), Expand5(px & 0x1Fu));
}

inline uint16_t PackRgb565(uint32_t xrgb) {
    return static_cast<uint16_t>((((xrgb >> 19) & 0x1Fu) << 11) |
                                 (((xrgb >> 10) & 0x3Fu) << 5) |
                                 ((xrgb >> 3) & 0x1Fu));
}

inline uint32_t MsbFirstShift(uint32_t bit, uint32_t bpp) { return 8u - bpp - (bit & 7u); }

inline uint32_t PackedIndexMsbFirst(const uint8_t* row, uint32_t x, uint32_t bpp) {
    const uint32_t bit = x * bpp;
    return (row[bit >> 3] >> MsbFirstShift(bit, bpp)) & ((1u << bpp) - 1u);
}

}
