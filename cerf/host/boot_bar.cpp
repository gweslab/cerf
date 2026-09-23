#define NOMINMAX

#include "boot_bar.h"

#include "../core/cerf_emulator.h"
#include "../lcd/lcd_pixel_expand.h"
#include "emulation_pause.h"
#include "uart_boot_bar_data.h"

REGISTER_SERVICE(BootBar);

void BootBar::RenderInto(uint32_t* dib_bgra32,
                         uint32_t width, uint32_t height) {
    if (height < kUartBootBarHeight || width == 0) return;

    const uint64_t cycle_ms = 4000;
    const uint32_t phase_ms =
        (uint32_t)(emu_.Get<EmulationPause>().AnimationTickMs() % cycle_ms);
    const int      x_origin = (int)(((uint64_t)phase_ms * width) / cycle_ms);
    const int      y_origin = (int)height - (int)kUartBootBarHeight;

    for (uint32_t py = 0; py < kUartBootBarHeight; ++py) {
        const int dst_y = y_origin + (int)py;
        if (dst_y < 0 || dst_y >= (int)height) continue;
        const uint32_t* src_row = &kUartBootBarPixels[py * kUartBootBarWidth];
        uint32_t*       dst_row = dib_bgra32 + (size_t)dst_y * width;
        for (uint32_t px = 0; px < kUartBootBarWidth; ++px) {
            const int dst_x = (x_origin + (int)px) % (int)width;
            const uint32_t s  = src_row[px];
            const uint32_t sa = (s >> 24) & 0xFFu;
            if (sa == 0) continue;
            const uint32_t sr = (s >> 16) & 0xFFu;
            const uint32_t sg = (s >>  8) & 0xFFu;
            const uint32_t sb =  s        & 0xFFu;
            const uint32_t d  = dst_row[dst_x];
            const uint32_t dr = (d >> 16) & 0xFFu;
            const uint32_t dg = (d >>  8) & 0xFFu;
            const uint32_t db =  d        & 0xFFu;
            const uint32_t inv = 255u - sa;
            const uint32_t out_r = (sr * sa + dr * inv) / 255u;
            const uint32_t out_g = (sg * sa + dg * inv) / 255u;
            const uint32_t out_b = (sb * sa + db * inv) / 255u;
            dst_row[dst_x] = lcd_pixel::PackXrgb(out_r, out_g, out_b);
        }
    }
}
