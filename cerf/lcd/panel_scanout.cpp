#include "panel_scanout.h"

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
                    const uint32_t v = (line[x >> 2] >> (6u - 2u * (x & 3u))) & 3u;
                    const uint32_t g = v * kGray2Step;
                    dst[x] = 0xFF000000u | (g << 16) | (g << 8) | g;
                }
                break;
            case PanelPixelFormat::kRgb565Le:
                for (uint32_t x = 0; x < cw; ++x) {
                    uint16_t px;
                    std::memcpy(&px, line + x * 2u, sizeof(px));
                    const uint32_t r5 = (px >> 11) & 0x1Fu;
                    const uint32_t g6 = (px >> 5)  & 0x3Fu;
                    const uint32_t b5 =  px        & 0x1Fu;
                    dst[x] = 0xFF000000u
                           | (((r5 << 3) | (r5 >> 2)) << 16)
                           | (((g6 << 2) | (g6 >> 4)) << 8)
                           |  ((b5 << 3) | (b5 >> 2));
                }
                break;
        }
    }
}
