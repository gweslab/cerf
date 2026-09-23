#define NOMINMAX

#include "s3c2410_lcd.h"

#include "../../boards/board_context.h"
#include "../../boards/smdk2410_devemu/devemu_id.h"
#include "../../boards/siemens_p177/siemens_p177_id.h"
#include "../../core/byte_order.h"
#include "../../core/cerf_emulator.h"
#include "../../cpu/emulated_memory.h"
#include "../../host/panel_frame_renderer.h"
#include "../../lcd/lcd_pixel_expand.h"

#include <cstring>

namespace {

class S3C2410LcdRenderer : public PanelFrameRenderer {
public:
    using PanelFrameRenderer::PanelFrameRenderer;

    bool ShouldRegister() override {
        /* Board-gated, not SoC-gated: which display path a board uses
           is board wiring. Both these S3C2410 boards drive the on-die
           LCDC - DevEmu's guest programs it at runtime; P177's
           bootloader presets it pre-kernel. */
        auto* bd = emu_.TryGet<BoardContext>();
        if (!bd) return false;
        const std::string_view b = bd->GetBoardId();
        return b == BoardId::Devemu || b == BoardId::SiemensP177;
    }

    void PresentedSize(uint32_t& w, uint32_t& h) override {
        auto& lcd = emu_.Get<S3C2410Lcd>();
        w = lcd.GetGuestW();
        h = lcd.GetGuestH();
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
                              * (size_t)lcd.GetBytesPerPixel();
        return latch_.ProbeAndLatch(emu_.Get<EmulatedMemory>(),
                                    fb_pa, fb_bytes);
    }

    void RenderInto(uint32_t* dib_bgra32,
                    uint32_t  host_w,
                    uint32_t  host_h) override {
        auto& lcd = emu_.Get<S3C2410Lcd>();
        const uint32_t fb_pa   = lcd.GetFbPa();
        const uint32_t guest_w = lcd.GetGuestW();
        const uint32_t guest_h = lcd.GetGuestH();
        const uint32_t bpp     = lcd.GetBytesPerPixel();
        const bool     pal     = lcd.IsPalettized();

        std::memset(dib_bgra32, 0, (size_t)host_w * host_h * 4u);

        const uint32_t copy_w = (guest_w < host_w) ? guest_w : host_w;
        const uint32_t copy_h = (guest_h < host_h) ? guest_h : host_h;
        if (copy_w == 0 || copy_h == 0) return;

        const uint8_t* src_base =
            emu_.Get<EmulatedMemory>().TryTranslate(fb_pa);
        if (!src_base) return;

        for (uint32_t y = 0; y < copy_h; ++y) {
            const uint8_t* src_row = src_base + (size_t)y * guest_w * bpp;
            uint32_t* dst_row = dib_bgra32 + (size_t)y * host_w;
            if (pal) {
                /* 8bpp: each byte indexes the 256-entry 5:6:5 palette. */
                for (uint32_t x = 0; x < copy_w; ++x)
                    dst_row[x] = lcd_pixel::Expand565(lcd.GetPaletteEntry565(src_row[x]));
            } else {
                for (uint32_t x = 0; x < copy_w; ++x)
                    dst_row[x] = lcd_pixel::Expand565(cerf::le::U16(src_row, (size_t)x * 2u));
            }
        }
    }

    std::optional<FbLayout> GetFbLayout() override {
        auto& lcd = emu_.Get<S3C2410Lcd>();
        const uint32_t pa = lcd.GetFbPa();
        if (pa == 0) return std::nullopt;
        const uint32_t bpp = lcd.GetBytesPerPixel();
        /* rgb565 flags a direct 5:6:5 framebuffer; the 8bpp path is
           palette-indexed, not 565 pixels. */
        return FbLayout{ pa, lcd.GetGuestW() * bpp, bpp * 8u, !lcd.IsPalettized() };
    }

private:
};

}  /* namespace */

REGISTER_SERVICE_AS(S3C2410LcdRenderer, PanelFrameRenderer);
