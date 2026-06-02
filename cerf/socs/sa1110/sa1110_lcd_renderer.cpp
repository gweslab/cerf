#define NOMINMAX

#include "sa1110_lcd.h"

#include "../../boards/board_detector.h"
#include "../../core/cerf_emulator.h"
#include "../../core/device_config.h"
#include "../../cpu/emulated_memory.h"
#include "../../host/frame_renderer.h"
#include "../../lcd/lcd_content_latch.h"

#include <cstring>

namespace {

/* SA-1110 §11.7.1.2: in active TFT 16-bpp mode (PBS=2, PAS=1), the
   frame buffer begins with a 32-byte dummy palette buffer that the
   LCD controller loads but does not use, followed by 16-bit pixel
   data laid out per Figure 11-9: R[15:11] G[10:5] B[4:0]. */

constexpr uint32_t kDummyPaletteBytes  = 32;
constexpr uint32_t kBytesPerGuestPixel = 2;
constexpr size_t   kContentProbeStride = 251;

class Sa1110LcdRenderer : public FrameRenderer {
public:
    using FrameRenderer::FrameRenderer;

    bool ShouldRegister() override {
        if (emu_.Get<DeviceConfig>().guest_additions) return false;
        auto* bd = emu_.TryGet<BoardDetector>();
        return bd && bd->GetSoc() == SocFamily::SA1110;
    }

    /* iPAQ panel is portrait; SA1110 LCD controller scans landscape.
       Renderer rotates 90° CCW (see RenderInto), so host window must
       receive swapped dims or the rotation math draws a square crop. */
    std::pair<uint32_t, uint32_t>
    HostSizeFor(uint32_t fb_w, uint32_t fb_h) const override {
        return {fb_h, fb_w};
    }

    bool HasFrame() override {
        auto& lcd = emu_.Get<Sa1110Lcd>();
        if (!lcd.IsEnabled())              return false;
        if (latch_.Latched())              return true;
        const uint32_t fb_pa   = lcd.GetFbPa();
        const uint32_t guest_w = lcd.GetGuestW();
        const uint32_t guest_h = lcd.GetGuestH();
        if (fb_pa == 0 || guest_w == 0 || guest_h == 0) return false;
        const size_t pixel_bytes = (size_t)guest_w * (size_t)guest_h
                                 * (size_t)kBytesPerGuestPixel;
        return latch_.ProbeAndLatch(emu_.Get<EmulatedMemory>(),
                                    fb_pa + kDummyPaletteBytes,
                                    pixel_bytes,
                                    kContentProbeStride);
    }

    void RenderInto(uint32_t* dib_bgra32,
                    uint32_t  host_w,
                    uint32_t  host_h) override {
        auto& lcd = emu_.Get<Sa1110Lcd>();
        const uint32_t fb_pa   = lcd.GetFbPa();
        const uint32_t guest_w = lcd.GetGuestW();
        const uint32_t guest_h = lcd.GetGuestH();

        std::memset(dib_bgra32, 0, (size_t)host_w * host_h * 4u);
        if (guest_w == 0 || guest_h == 0) return;

        const uint8_t* fb_base = emu_.Get<EmulatedMemory>().TryTranslate(fb_pa);
        if (!fb_base) return;
        const uint16_t* pixels = reinterpret_cast<const uint16_t*>(
            fb_base + kDummyPaletteBytes);

        /* Host window is portrait (panel orientation); FB is landscape.
           Rotate 90° CCW: dest(x_dst, y_dst) = src(W_src - 1 - y_dst, x_dst).
           Iterate dest row-major for cache locality on the write side. */
        const uint32_t copy_w = (host_w < guest_h) ? host_w : guest_h;
        const uint32_t copy_h = (host_h < guest_w) ? host_h : guest_w;
        for (uint32_t y_dst = 0; y_dst < copy_h; ++y_dst) {
            const uint32_t x_src = guest_w - 1u - y_dst;
            uint32_t* dst_row = dib_bgra32 + (size_t)y_dst * host_w;
            for (uint32_t x_dst = 0; x_dst < copy_w; ++x_dst) {
                const uint32_t y_src = x_dst;
                const uint16_t p  = pixels[(size_t)y_src * guest_w + x_src];
                const uint8_t  r5 = (p >> 11) & 0x1Fu;
                const uint8_t  g6 = (p >>  5) & 0x3Fu;
                const uint8_t  b5 =  p        & 0x1Fu;
                const uint8_t  r  = (uint8_t)((r5 << 3) | (r5 >> 2));
                const uint8_t  g  = (uint8_t)((g6 << 2) | (g6 >> 4));
                const uint8_t  b  = (uint8_t)((b5 << 3) | (b5 >> 2));
                dst_row[x_dst] = 0xFF000000u | ((uint32_t)r << 16)
                                             | ((uint32_t)g <<  8)
                                             |  (uint32_t)b;
            }
        }
    }

    std::optional<FbLayout> GetFbLayout() override {
        auto& lcd = emu_.Get<Sa1110Lcd>();
        const uint32_t pa = lcd.GetFbPa();
        if (pa == 0) return std::nullopt;
        /* Pixel data follows the 32-byte dummy palette buffer (§11.7.1.2). */
        return FbLayout{ pa + kDummyPaletteBytes,
                         lcd.GetGuestW() * kBytesPerGuestPixel, 16u, true };
    }

private:
    LcdContentLatch latch_;
};

}  /* namespace */

REGISTER_SERVICE_AS(Sa1110LcdRenderer, FrameRenderer);
