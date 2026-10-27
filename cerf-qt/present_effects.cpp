#include "present_effects.h"

#include <cerfcore/lcd/lcd_pixel_expand.h>

namespace cerffrontend {

namespace {

constexpr uint32_t kPausedColorQ10 = 416;
constexpr uint32_t kPausedLumaQ10  = 250;

}

void PresentEffects::DesaturateAndDim(uint32_t* pixels, int count) {
    for (int i = 0; i < count; ++i) {
        const uint32_t p = pixels[i];
        const uint32_t r = (p >> 16) & 0xFFu;
        const uint32_t g = (p >> 8) & 0xFFu;
        const uint32_t b = p & 0xFFu;
        const uint32_t y = cerfcore::lcd_pixel::Luma8(p) * kPausedLumaQ10;
        pixels[i] = (p & 0xFF000000u) | (((r * kPausedColorQ10 + y) >> 10) << 16) |
                    (((g * kPausedColorQ10 + y) >> 10) << 8) | ((b * kPausedColorQ10 + y) >> 10);
    }
}

}
