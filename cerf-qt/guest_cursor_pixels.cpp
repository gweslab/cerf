#include "guest_cursor_pixels.h"

#include <cerfcore/lcd/lcd_pixel_expand.h>
#include <cerfcore/peripherals/cerf_virt/cerf_virt_cursor.h>

namespace cerffrontend {

std::vector<CursorPixel> GuestCursorPixels::Decode(const cerfcore::GuestCursorShape& s) {
    std::vector<CursorPixel> out(static_cast<size_t>(s.cx) * s.cy, CursorPixel::kTransparent);
    for (uint32_t row = 0; row < s.cy; ++row) {
        const uint8_t* and_row = s.bits.data() + static_cast<size_t>(row) * s.stride;
        const uint8_t* xor_row = s.bits.data() + static_cast<size_t>(s.cy + row) * s.stride;
        for (uint32_t col = 0; col < s.cx; ++col) {
            const uint8_t mask =
                static_cast<uint8_t>(1u << cerfcore::lcd_pixel::MsbFirstShift(col, 1u));
            const bool and_bit = (and_row[col >> 3] & mask) != 0;
            const bool xor_bit = (xor_row[col >> 3] & mask) != 0;
            CursorPixel& px    = out[static_cast<size_t>(row) * s.cx + col];
            if (and_bit) px = xor_bit ? CursorPixel::kInvert : CursorPixel::kTransparent;
            else         px = xor_bit ? CursorPixel::kWhite : CursorPixel::kBlack;
        }
    }
    return out;
}

}
