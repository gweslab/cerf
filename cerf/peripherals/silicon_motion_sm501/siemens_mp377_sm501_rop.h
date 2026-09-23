#pragma once

#include "../../core/byte_order.h"

#include <cstdint>

/* SM501 Databook v1.02, section 4, 2D raster operations. */
inline bool Sm501Rop3Bit(uint8_t rop, bool p, bool s, bool d) {
    const unsigned index = (p ? 4u : 0u) | (s ? 2u : 0u) | (d ? 1u : 0u);
    return ((rop >> index) & 1u) != 0u;
}

inline bool Sm501RopDependsOnSource(uint8_t rop) {
    for (unsigned p = 0; p < 2; ++p) {
        for (unsigned d = 0; d < 2; ++d) {
            if (Sm501Rop3Bit(rop, p != 0, false, d != 0) !=
                Sm501Rop3Bit(rop, p != 0, true, d != 0)) {
                return true;
            }
        }
    }
    return false;
}

/* SM501 Databook v1.02, section 4, 2D Control bits 15:14 and 7:0. */
inline bool Sm501RasterOpDependsOnSource(uint32_t control) {
    if ((control & (1u << 15)) == 0u) {
        return Sm501RopDependsOnSource(static_cast<uint8_t>(control));
    }
    return (control & (1u << 14)) == 0u;
}

inline uint16_t Sm501ApplyRop16(uint8_t rop, uint16_t source,
                                uint16_t destination, uint16_t pattern) {
    uint16_t result = 0;
    for (unsigned bit = 0; bit < 16; ++bit) {
        const bool p = ((pattern >> bit) & 1u) != 0u;
        const bool s = ((source >> bit) & 1u) != 0u;
        const bool d = ((destination >> bit) & 1u) != 0u;
        if (Sm501Rop3Bit(rop, p, s, d)) {
            result |= static_cast<uint16_t>(1u << bit);
        }
    }
    return result;
}

/* SM501 Databook v1.02, 2D Control bits 15:14. */
inline uint16_t Sm501ApplyRasterOp16(uint32_t control, uint16_t source,
                                     uint16_t destination, uint16_t pattern) {
    const uint8_t rop = static_cast<uint8_t>(control);
    if ((control & (1u << 15)) == 0u) {
        return Sm501ApplyRop16(rop, source, destination, pattern);
    }
    const uint16_t operand = (control & (1u << 14)) != 0u ? pattern : source;
    uint16_t result = 0;
    for (unsigned bit = 0; bit < 16; ++bit) {
        const unsigned index = (((operand >> bit) & 1u) << 1) |
                               ((destination >> bit) & 1u);
        if (((rop >> index) & 1u) != 0u) {
            result |= static_cast<uint16_t>(1u << bit);
        }
    }
    return result;
}

inline void Sm501RasterOpPixel16(uint8_t* pixel, uint32_t control, uint16_t source, uint16_t pattern) {
    cerf::le::Put16(pixel, Sm501ApplyRasterOp16(control, source, cerf::le::U16(pixel), pattern));
}
