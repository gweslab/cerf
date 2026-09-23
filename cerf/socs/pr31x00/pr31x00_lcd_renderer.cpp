#define NOMINMAX

#include "pr31x00_lcd.h"

#include "../../boards/board_context.h"
#include "pr31500_id.h"
#include "pr31700_id.h"
#include "../../core/cerf_emulator.h"
#include "../../cpu/emulated_memory.h"
#include "../../host/panel_frame_renderer.h"
#include "../../lcd/lcd_pixel_expand.h"

#include <cstring>

namespace {

/* The gray modes vary a pixel's duty cycle over frames so the monochrome panel
   takes on one of 16 shades (§17.3.7). */
inline uint32_t ExpandShade(uint32_t shade) {
    const uint32_t g = lcd_pixel::Expand4(shade);
    return lcd_pixel::PackXrgb(g, g, g);
}

class Pr31x00LcdRenderer : public PanelFrameRenderer {
public:
    using PanelFrameRenderer::PanelFrameRenderer;

    bool ShouldRegister() override {
        auto* bd = emu_.TryGet<BoardContext>();
        if (!bd) return false;
        const std::string_view soc = bd->GetSocId();
        return soc == SocId::Pr31500 || soc == SocId::Pr31700;
    }

    void PresentedSize(uint32_t& w, uint32_t& h) override {
        auto& lcd = emu_.Get<Pr31x00Lcd>();
        w = lcd.GetGuestW();
        h = lcd.GetGuestH();
    }

    bool HasFrame() override {
        auto& lcd = emu_.Get<Pr31x00Lcd>();
        if (!lcd.IsEnabled())  return false;
        if (latch_.Latched())  return true;
        const uint32_t fb_pa   = lcd.GetFbPa();
        const uint32_t guest_w = lcd.GetGuestW();
        const uint32_t guest_h = lcd.GetGuestH();
        if (fb_pa == 0 || guest_w == 0 || guest_h == 0) return false;
        const size_t fb_bytes =
            (size_t)guest_h * (size_t)guest_w * lcd.GetBitsPerPixel() / 8u;
        return latch_.ProbeAndLatch(emu_.Get<EmulatedMemory>(),
                                    fb_pa, fb_bytes);
    }

    void RenderInto(uint32_t* dib_bgra32, uint32_t host_w, uint32_t host_h) override {
        auto& lcd = emu_.Get<Pr31x00Lcd>();
        const uint32_t fb_pa   = lcd.GetFbPa();
        const uint32_t guest_w = lcd.GetGuestW();
        const uint32_t guest_h = lcd.GetGuestH();
        const uint32_t bpp     = lcd.GetBitsPerPixel();

        std::memset(dib_bgra32, 0, (size_t)host_w * host_h * 4u);

        const uint32_t copy_w = (guest_w < host_w) ? guest_w : host_w;
        const uint32_t copy_h = (guest_h < host_h) ? guest_h : host_h;
        if (copy_w == 0 || copy_h == 0) return;

        const uint8_t* src_base = emu_.Get<EmulatedMemory>().TryTranslate(fb_pa);
        if (!src_base) return;

        const size_t stride = (size_t)guest_w * bpp / 8u;
        for (uint32_t y = 0; y < copy_h; ++y) {
            const uint8_t* src_row = src_base + (size_t)y * stride;
            uint32_t* dst_row = dib_bgra32 + (size_t)y * host_w;
            for (uint32_t x = 0; x < copy_w; ++x) {
                /* Figure 17.2.1: the leftmost pixels of a line are driven by UD3, UD2, UD1, UD0,
                   so a byte's most significant bits hold the leftmost pixel. */
                dst_row[x] = ExpandShade(lcd.ShadeFor(lcd_pixel::PackedIndexMsbFirst(src_row, x, bpp)));
            }
        }
    }

    std::optional<FbLayout> GetFbLayout() override {
        auto& lcd = emu_.Get<Pr31x00Lcd>();
        const uint32_t pa = lcd.GetFbPa();
        if (pa == 0) return std::nullopt;
        const uint32_t bpp = lcd.GetBitsPerPixel();
        return FbLayout{ pa, lcd.GetGuestW() * bpp / 8u, bpp, false };
    }
};

}  /* namespace */

REGISTER_SERVICE_AS(Pr31x00LcdRenderer, PanelFrameRenderer);
