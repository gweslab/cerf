#define NOMINMAX

#include "pxa27x_lcd.h"

#include "../../boards/board_context.h"
#include "../../core/cerf_emulator.h"
#include "../../core/log.h"
#include "../../cpu/emulated_memory.h"
#include "../../host/panel_frame_renderer.h"
#include "../../lcd/lcd_pixel_expand.h"

#include <cstring>

namespace {

constexpr size_t kContentProbeStride = 251;

/* Intel PXA27x Developer's Manual 280000-001 Table 7-43: BPP3:BPP = 0b0100
   selects 16 bpp with no palette. Section 7.4.1.3: the palette RAM is bypassed
   for pixel depth greater than 8 bpp. */
constexpr uint32_t kBppCode16Bpp = 0x4u;
constexpr uint32_t kBytesPerPixel16Bpp = 2u;

class Pxa27xLcdRenderer : public PanelFrameRenderer {
public:
    using PanelFrameRenderer::PanelFrameRenderer;

    bool ShouldRegister() override {
        auto* bd = emu_.TryGet<BoardContext>();
        return bd && bd->GetSoc() == SocFamily::PXA27x;
    }

    void PresentedSize(uint32_t& w, uint32_t& h) override {
        auto& lcd = emu_.Get<Pxa27xLcd>();
        w = lcd.GetGuestW();
        h = lcd.GetGuestH();
    }

    bool HasFrame() override {
        auto& lcd = emu_.Get<Pxa27xLcd>();
        if (!lcd.IsEnabled())  return false;
        RequireSupportedMode(lcd);
        if (latch_.Latched())  return true;

        const uint32_t fb_pa   = lcd.GetChannelSrcPa(0);
        const uint32_t guest_w = lcd.GetGuestW();
        const uint32_t guest_h = lcd.GetGuestH();
        if (fb_pa == 0 || guest_w == 0 || guest_h == 0) return false;

        const size_t fb_bytes = (size_t)guest_w * (size_t)guest_h
                              * (size_t)kBytesPerPixel16Bpp;
        return latch_.ProbeAndLatch(emu_.Get<EmulatedMemory>(),
                                    fb_pa, fb_bytes, kContentProbeStride);
    }

    void RenderInto(uint32_t* dib_bgra32,
                    uint32_t  host_w,
                    uint32_t  host_h) override {
        auto& lcd = emu_.Get<Pxa27xLcd>();
        RequireSupportedMode(lcd);

        const uint32_t fb_pa   = lcd.GetChannelSrcPa(0);
        const uint32_t guest_w = lcd.GetGuestW();
        const uint32_t guest_h = lcd.GetGuestH();

        std::memset(dib_bgra32, 0, (size_t)host_w * host_h * 4u);

        const uint32_t copy_w = (guest_w < host_w) ? guest_w : host_w;
        const uint32_t copy_h = (guest_h < host_h) ? guest_h : host_h;
        if (copy_w == 0 || copy_h == 0) return;

        const uint8_t* src_base = emu_.Get<EmulatedMemory>().TryTranslate(fb_pa);
        if (!src_base) return;

        /* Intel PXA27x Developer's Manual 280000-001 Figure 7-25: at 16 bpp with
           overlays disabled the base frame is RGB565, two pixels per word, pixel
           0 in the low half. Section 7.4.13: each line in memory must start at a
           word boundary. */
        for (uint32_t y = 0; y < copy_h; ++y) {
            const uint16_t* src_row = reinterpret_cast<const uint16_t*>(
                src_base + (size_t)y * guest_w * kBytesPerPixel16Bpp);
            uint32_t* dst_row = dib_bgra32 + (size_t)y * host_w;
            for (uint32_t x = 0; x < copy_w; ++x)
                dst_row[x] = lcd_pixel::Expand565(src_row[x]);
        }
    }

    std::optional<FbLayout> GetFbLayout() override {
        auto& lcd = emu_.Get<Pxa27xLcd>();
        const uint32_t pa = lcd.GetChannelSrcPa(0);
        if (pa == 0) return std::nullopt;
        return FbLayout{ pa,
                         lcd.GetGuestW() * kBytesPerPixel16Bpp,
                         kBytesPerPixel16Bpp * 8u,
                         true };
    }

private:
    /* Intel PXA27x Developer's Manual 280000-001 Section 7.5.2: all bits in the
       control registers must be programmed before setting LCCR0[ENB]. */
    void RequireSupportedMode(Pxa27xLcd& lcd) {
        const uint32_t bpp = lcd.GetBppCode();
        if (bpp != kBppCode16Bpp) {
            LOG(Caution, "PXA27x LCD BPP3:BPP code 0x%X is not modelled\n", bpp);
            CerfFatalExit(CERF_FATAL_RUNTIME_ERROR);
        }
        if (lcd.ChannelIsPalette(0)) {
            LOG(Caution, "PXA27x LCD channel 0 loaded a palette descriptor\n");
            CerfFatalExit(CERF_FATAL_RUNTIME_ERROR);
        }
    }
};

}

REGISTER_SERVICE_AS(Pxa27xLcdRenderer, PanelFrameRenderer);
