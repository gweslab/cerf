#define NOMINMAX

#include "s3c2410_lcd.h"

#include "../../boards/board_detector.h"
#include "../../core/cerf_emulator.h"
#include "../../core/device_config.h"
#include "../../cpu/emulated_memory.h"
#include "../../host/frame_renderer.h"
#include "../../lcd/lcd_content_latch.h"

#include <cstring>

namespace {

/* 16bpp 5:6:5: R[15:11] G[10:5] B[4:0]. */
constexpr uint32_t kBytesPerGuestPixel = 2;

/* Sample stride for the content-latch probe. Relatively prime to a
   2-byte row pitch so the sample pattern doesn't degenerate to a
   single column on power-of-two widths. */
constexpr size_t   kContentProbeStride = 251;

class S3C2410LcdRenderer : public FrameRenderer {
public:
    using FrameRenderer::FrameRenderer;

    bool ShouldRegister() override {
        if (emu_.Get<DeviceConfig>().guest_additions) return false;
        auto* bd = emu_.TryGet<BoardDetector>();
        return bd && bd->GetSoc() == SocFamily::S3C2410;
    }

    bool HasFrame() override {
        auto& lcd = emu_.Get<S3C2410Lcd>();
        if (!lcd.IsEnabled())              return false;
        if (latch_.Latched())              return true;
        const uint32_t fb_pa   = lcd.GetFbPa();
        const uint32_t guest_w = lcd.GetGuestW();
        const uint32_t guest_h = lcd.GetGuestH();
        if (fb_pa == 0 || guest_w == 0 || guest_h == 0) return false;
        const size_t fb_bytes = (size_t)guest_w * (size_t)guest_h
                              * (size_t)kBytesPerGuestPixel;
        return latch_.ProbeAndLatch(emu_.Get<EmulatedMemory>(),
                                    fb_pa, fb_bytes,
                                    kContentProbeStride);
    }

    void RenderInto(uint32_t* dib_bgra32,
                    uint32_t  host_w,
                    uint32_t  host_h) override {
        auto& lcd = emu_.Get<S3C2410Lcd>();
        const uint32_t fb_pa   = lcd.GetFbPa();
        const uint32_t guest_w = lcd.GetGuestW();
        const uint32_t guest_h = lcd.GetGuestH();

        std::memset(dib_bgra32, 0, (size_t)host_w * host_h * 4u);

        const uint32_t copy_w = (guest_w < host_w) ? guest_w : host_w;
        const uint32_t copy_h = (guest_h < host_h) ? guest_h : host_h;
        if (copy_w == 0 || copy_h == 0) return;

        const uint8_t* src_base =
            emu_.Get<EmulatedMemory>().TryTranslate(fb_pa);
        if (!src_base) return;

        /* 5:6:5 → BGRA8888. Top bits replicated so 0x1F → 0xFF and
           0x3F → 0xFF (clean expansion to the full 8-bit range). */
        for (uint32_t y = 0; y < copy_h; ++y) {
            const uint16_t* src_row = reinterpret_cast<const uint16_t*>(
                src_base + (size_t)y * guest_w * kBytesPerGuestPixel);
            uint32_t* dst_row = dib_bgra32 + (size_t)y * host_w;
            for (uint32_t x = 0; x < copy_w; ++x) {
                const uint16_t px = src_row[x];
                const uint8_t  r5 = (px >> 11) & 0x1Fu;
                const uint8_t  g6 = (px >>  5) & 0x3Fu;
                const uint8_t  b5 =  px        & 0x1Fu;
                const uint8_t  r  = (uint8_t)((r5 << 3) | (r5 >> 2));
                const uint8_t  g  = (uint8_t)((g6 << 2) | (g6 >> 4));
                const uint8_t  b  = (uint8_t)((b5 << 3) | (b5 >> 2));
                dst_row[x] = 0xFF000000u | ((uint32_t)r << 16)
                                         | ((uint32_t)g <<  8)
                                         |  (uint32_t)b;
            }
        }
    }

    std::optional<FbLayout> GetFbLayout() override {
        auto& lcd = emu_.Get<S3C2410Lcd>();
        const uint32_t pa = lcd.GetFbPa();
        if (pa == 0) return std::nullopt;
        return FbLayout{ pa, lcd.GetGuestW() * kBytesPerGuestPixel, 16u, true };
    }

private:
    LcdContentLatch latch_;
};

}  /* namespace */

REGISTER_SERVICE_AS(S3C2410LcdRenderer, FrameRenderer);
