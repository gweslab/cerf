#define NOMINMAX

#include "ati_ragexl_display.h"

#include "../../core/byte_order.h"
#include "../../core/cerf_emulator.h"
#include "../../host/panel_frame_renderer.h"
#include "../../lcd/lcd_pixel_expand.h"

#include <cstring>

namespace {

/* Presents the Rage XL framebuffer at the CRTC-programmed geometry. The Mach64
   stores direct-colour pixels little-endian as B,G,R(,X); 16/15 bpp are 5-6-5 /
   5-5-5 (ati Programmer's Guide pixel formats). */
class AtiRageXlRenderer : public PanelFrameRenderer {
public:
    using PanelFrameRenderer::PanelFrameRenderer;

    bool ShouldRegister() override {
        return emu_.TryGet<RageXlDisplay>() != nullptr;
    }

    void PresentedSize(uint32_t& w, uint32_t& h) override {
        const auto f = emu_.Get<RageXlDisplay>().CurrentFrame();
        w = f.on ? f.width  : 0u;
        h = f.on ? f.height : 0u;
    }

    bool HasFrame() override {
        const auto f = emu_.Get<RageXlDisplay>().CurrentFrame();
        if (!f.on || f.bpp == 0 || f.stride == 0 || f.width == 0 || f.height == 0)
            return false;
        const size_t bytes = (size_t)f.stride * f.height;
        if ((size_t)f.start + bytes > f.fb_size) return false;
        if (latch_.Latched()) return true;
        return latch_.ProbeAndLatch(f.fb + f.start, bytes);
    }

    void RenderInto(uint32_t* dib, uint32_t host_w, uint32_t host_h) override {
        std::memset(dib, 0, (size_t)host_w * host_h * 4u);
        const auto f = emu_.Get<RageXlDisplay>().CurrentFrame();
        if (!f.on || f.bpp == 0 || f.stride == 0) return;

        const uint32_t cw = (host_w < f.width)  ? host_w : f.width;
        const uint32_t ch = (host_h < f.height) ? host_h : f.height;
        for (uint32_t y = 0; y < ch; ++y) {
            const size_t line_off = (size_t)f.start + (size_t)y * f.stride;
            if (line_off + (size_t)cw * ((f.bpp + 7u) / 8u) > f.fb_size) break;
            const uint8_t* line = f.fb + line_off;
            uint32_t* dst = dib + (size_t)y * host_w;
            for (uint32_t x = 0; x < cw; ++x) dst[x] = DecodePixel(line, x, f.bpp);
        }

        const auto cur = emu_.Get<RageXlDisplay>().CurrentCursor();
        if (cur.enabled && cur.def) CompositeCursor(dib, host_w, cw, ch, cur);
    }

private:
    static void CompositeCursor(uint32_t* dib, uint32_t host_w, uint32_t cw,
                                uint32_t ch, const RageXlDisplay::Cursor& cur) {
        const uint32_t rows = (cur.visible_h < 64u) ? cur.visible_h : 64u;
        const uint32_t cols = (cur.visible_w < 64u) ? cur.visible_w : 64u;
        for (uint32_t row = 0; row < rows; ++row) {
            const int sy = cur.y + static_cast<int>(row);
            if (sy < 0 || static_cast<uint32_t>(sy) >= ch) continue;
            const uint8_t* rp = cur.def + (size_t)row * 16u;
            uint16_t w[8];
            for (uint32_t k = 0; k < 8; ++k) w[k] = cerf::le::U16(rp, (k * 2u + 8u) % 16u);
            uint32_t* dst = dib + (size_t)sy * host_w;
            for (uint32_t col = 0; col < cols; ++col) {
                const int sx = cur.x + static_cast<int>(col);
                if (sx < 0 || static_cast<uint32_t>(sx) >= cw) continue;
                switch ((w[col >> 3] >> ((col & 7u) * 2u)) & 3u) {
                    case 0: dst[sx] = 0xFF000000u | cur.clr0; break;
                    case 1: dst[sx] = 0xFF000000u | cur.clr1; break;
                    case 2: break;
                    case 3: dst[sx] = 0xFF000000u | (~dst[sx] & 0xFFFFFFu); break;
                }
            }
        }
    }

    static uint32_t DecodePixel(const uint8_t* line, uint32_t x, uint32_t bpp) {
        switch (bpp) {
            case 32: return 0xFF000000u | cerf::le::U24(line, x * 4u);
            case 24: return 0xFF000000u | cerf::le::U24(line, x * 3u);
            case 16: return lcd_pixel::Expand565(cerf::le::U16(line, x * 2u));
            case 15: return lcd_pixel::Expand555(cerf::le::U16(line, x * 2u));
            default: { const uint8_t g = line[x]; return lcd_pixel::PackXrgb(g, g, g); }
        }
    }
};

}  /* namespace */

REGISTER_SERVICE_AS(AtiRageXlRenderer, PanelFrameRenderer);
