#define NOMINMAX

#include "../../socs/sa11xx/sa11xx_lcd.h"

#include "../../boards/board_context.h"
#include "jornada_820_id.h"
#include "../../core/byte_order.h"
#include "../../core/cerf_emulator.h"
#include "../../cpu/emulated_memory.h"
#include "../../host/panel_frame_renderer.h"
#include "../../lcd/lcd_pixel_expand.h"

#include <cstring>

namespace {

/* SA-1100 8bpp dual-panel STN (Dev Man §11.7.1.2 / Fig 11-3): DBAR1 =
   [512B 256-entry palette][upper 640x240 8bpp]; DBAR2 = [lower 640x240]
   (no palette). Palette entry: R=bits 11:8, G=7:4, B=3:0. Landscape, no
   rotation. */

constexpr uint32_t kPaletteBytes = 512;  /* 256 entries x 2 bytes (8bpp) */

class Jornada820LcdRenderer : public PanelFrameRenderer {
public:
    using PanelFrameRenderer::PanelFrameRenderer;

    bool ShouldRegister() override {
        auto* bd = emu_.TryGet<BoardContext>();
        return bd && bd->GetBoardId() == BoardId::Jornada820;
    }

    void PresentedSize(uint32_t& w, uint32_t& h) override {
        auto& lcd = emu_.Get<Sa11xxLcd>();
        w = lcd.GetGuestW();
        h = lcd.GetGuestH();
    }

    bool HasFrame() override {
        auto& lcd = emu_.Get<Sa11xxLcd>();
        if (!lcd.IsEnabled())  return false;
        if (latch_.Latched())  return true;
        const uint32_t dbar1   = lcd.GetFbPa();
        const uint32_t guest_w = lcd.GetGuestW();
        const uint32_t guest_h = lcd.GetGuestH();
        if (dbar1 == 0 || guest_w == 0 || guest_h == 0) return false;
        const size_t upper_bytes = (size_t)guest_w * (guest_h / 2u);
        return latch_.ProbeAndLatch(emu_.Get<EmulatedMemory>(),
                                    dbar1 + kPaletteBytes, upper_bytes);
    }

    void RenderInto(uint32_t* dib_bgra32,
                    uint32_t  host_w,
                    uint32_t  host_h) override {
        std::memset(dib_bgra32, 0, (size_t)host_w * host_h * 4u);

        auto& lcd = emu_.Get<Sa11xxLcd>();
        const uint32_t guest_w = lcd.GetGuestW();
        const uint32_t guest_h = lcd.GetGuestH();
        if (guest_w == 0 || guest_h == 0) return;

        auto& mem = emu_.Get<EmulatedMemory>();
        const uint8_t* upper = mem.TryTranslate(lcd.GetFbPa());   /* DBAR1 */
        const uint8_t* lower = mem.TryTranslate(lcd.GetDbar2Pa()); /* DBAR2 */
        if (!upper || !lower) return;

        uint32_t lut[256];
        for (uint32_t i = 0; i < 256; ++i) {
            const uint16_t e = cerf::le::U16(upper, i * 2);
            lut[i] = lcd_pixel::PackXrgb(lcd_pixel::Expand4((e >> 8) & 0xFu),
                                         lcd_pixel::Expand4((e >> 4) & 0xFu),
                                         lcd_pixel::Expand4(e & 0xFu));
        }

        const uint32_t panel_h    = guest_h / 2u;
        const uint8_t* upper_px   = upper + kPaletteBytes;
        const uint32_t copy_w     = (host_w < guest_w) ? host_w : guest_w;
        const uint32_t copy_h     = (host_h < guest_h) ? host_h : guest_h;
        for (uint32_t y = 0; y < copy_h; ++y) {
            const uint8_t* src_row = (y < panel_h)
                ? upper_px + (size_t)y * guest_w
                : lower    + (size_t)(y - panel_h) * guest_w;
            uint32_t* dst_row = dib_bgra32 + (size_t)y * host_w;
            for (uint32_t x = 0; x < copy_w; ++x) dst_row[x] = lut[src_row[x]];
        }
    }

    std::optional<FbLayout> GetFbLayout() override {
        auto& lcd = emu_.Get<Sa11xxLcd>();
        const uint32_t dbar1 = lcd.GetFbPa();
        if (dbar1 == 0) return std::nullopt;
        return FbLayout{ dbar1 + kPaletteBytes, lcd.GetGuestW(), 8u, false };
    }
};

}  /* namespace */

REGISTER_SERVICE_AS(Jornada820LcdRenderer, PanelFrameRenderer);
