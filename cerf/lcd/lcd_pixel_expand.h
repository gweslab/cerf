#pragma once

#include <cstdint>

namespace lcd_pixel {

inline uint32_t Expand565(uint16_t px) {
    const uint8_t r5 = (px >> 11) & 0x1Fu;
    const uint8_t g6 = (px >>  5) & 0x3Fu;
    const uint8_t b5 =  px        & 0x1Fu;
    const uint8_t r  = static_cast<uint8_t>((r5 << 3) | (r5 >> 2));
    const uint8_t g  = static_cast<uint8_t>((g6 << 2) | (g6 >> 4));
    const uint8_t b  = static_cast<uint8_t>((b5 << 3) | (b5 >> 2));
    return 0xFF000000u | (static_cast<uint32_t>(r) << 16)
                       | (static_cast<uint32_t>(g) << 8) | b;
}

}
