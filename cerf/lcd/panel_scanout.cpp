#include "panel_scanout.h"

#include "lcd_pixel_expand.h"
#include "../core/byte_order.h"

#include <cstring>

constexpr uint32_t kGray2Step = 255u / 3u;

void PanelScanout::Blit(const PanelSurface& src, uint32_t* dib,
                        uint32_t host_w, uint32_t host_h) const {
    std::memset(dib, 0, static_cast<size_t>(host_w) * host_h * 4u);

    const uint32_t cw = (host_w < src.width)  ? host_w : src.width;
    const uint32_t ch = (host_h < src.height) ? host_h : src.height;

    for (uint32_t y = 0; y < ch; ++y) {
        const uint8_t* line = src.fb + static_cast<size_t>(y) * src.stride;
        uint32_t*      dst  = dib + static_cast<size_t>(y) * host_w;
        switch (format_) {
            case PanelPixelFormat::kGray2Msb:
                for (uint32_t x = 0; x < cw; ++x) {
                    const uint32_t g = lcd_pixel::PackedIndexMsbFirst(line, x, 2u) * kGray2Step;
                    dst[x] = lcd_pixel::PackXrgb(g, g, g);
                }
                break;
            case PanelPixelFormat::kRgb565Le:
                for (uint32_t x = 0; x < cw; ++x)
                    dst[x] = lcd_pixel::Expand565(cerf::le::U16(line, x * 2u));
                break;
        }
    }
}
