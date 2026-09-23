#define NOMINMAX

#include "sed1356.h"

#include "sed1356_config.h"
#include "../../core/cerf_emulator.h"
#include "../../core/log.h"
#include "../../host/panel_frame_renderer.h"
#include "../../lcd/lcd_pixel_expand.h"

#include <cstring>

namespace {

/* S1D13506 LCD pipe -> host BGRA. Pixel formats per Technical Manual §11.1:
   16 bpp 5-6-5, 15 bpp 5-5-5, 4/8 bpp through the 4-bit LCD LUT. */
class Sed1356Renderer : public PanelFrameRenderer {
public:
    using PanelFrameRenderer::PanelFrameRenderer;

    bool ShouldRegister() override {
        return emu_.TryGet<Sed1356Config>() != nullptr;
    }

    void PresentedSize(uint32_t& w, uint32_t& h) override {
        auto& sed = emu_.Get<Sed1356>();
        w = sed.LcdGuestW();
        h = sed.LcdGuestH();
    }

    bool HasFrame() override {
        auto& sed = emu_.Get<Sed1356>();
        if (!sed.LcdDisplayOn()) return false;
        if (latch_.Latched())    return true;
        const uint32_t bpp    = sed.LcdBpp();
        const uint32_t stride = sed.LcdStrideBytes();
        const uint32_t start  = sed.VramWrap(sed.LcdStartByte());
        if (bpp == 0 || stride == 0) return false;
        const size_t bytes = (size_t)stride * sed.LcdGuestH();
        if (start + bytes > sed.VramSize()) return false;
        return latch_.ProbeAndLatch(sed.VramData() + start, bytes);
    }

    void RenderInto(uint32_t* dib, uint32_t host_w, uint32_t host_h) override {
        std::memset(dib, 0, (size_t)host_w * host_h * 4u);

        auto& sed = emu_.Get<Sed1356>();
        if (sed.LcdBlanked()) return;          /* REG[040h].7: outputs zeroed. */

        const uint32_t swivel = sed.SwivelMode();
        if (swivel == 1u || swivel == 3u) {    /* Table 8-19: 90/270 degrees. */
            LOG(Caution, "Sed1356Renderer: SwivelView %u-degree mode is not "
                "implemented\n", swivel * 90u);
            CerfFatalExit(CERF_FATAL_RUNTIME_ERROR);
        }

        const uint32_t gw     = sed.LcdGuestW(), gh = sed.LcdGuestH();
        const uint32_t bpp    = sed.LcdBpp();
        const uint32_t stride = sed.LcdStrideBytes();
        const uint32_t start  = sed.VramWrap(sed.LcdStartByte());
        if (gw == 0 || gh == 0 || bpp == 0 || stride == 0) return;

        /* REG[048h] pans the display left; bits used per depth (Table 8-21):
           4 bpp -> [1:0], 8 bpp -> [0], 15/16 bpp -> none. */
        uint32_t pan = sed.LcdPixelPan();
        if (bpp == 8u)       pan &= 0x1u;
        else if (bpp >= 15u) pan = 0;

        const uint8_t* vram = sed.VramData();

        const uint32_t cw = (host_w < gw) ? host_w : gw;
        const uint32_t ch = (host_h < gh) ? host_h : gh;
        for (uint32_t y = 0; y < ch; ++y) {
            uint32_t* dst = dib + (size_t)y * host_w;
            const uint32_t sy = (swivel == 2u) ? gh - 1u - y : y;
            const uint32_t line = sed.VramWrap(start + sy * stride);
            for (uint32_t x = 0; x < cw; ++x) {
                const uint32_t sx = ((swivel == 2u) ? gw - 1u - x : x) + pan;
                dst[x] = DecodePixel(sed, vram, line, sx, bpp);
            }
        }

        ComposeInkCursor(sed, dib, host_w, cw, ch, gw, gh);
    }

    std::optional<FbLayout> GetFbLayout() override {
        auto& sed = emu_.Get<Sed1356>();
        const uint32_t bpp = sed.LcdBpp();
        if (!sed.LcdDisplayOn() || bpp == 0) return std::nullopt;
        return FbLayout{ sed.MmioBase() + 0x200000u + sed.LcdStartByte(),
                         sed.LcdStrideBytes(), bpp, bpp == 16u };
    }

private:
    static uint32_t FromLut(Sed1356& sed, uint32_t index) {
        uint8_t r4, g4, b4;
        sed.LcdLutRgb(index, r4, g4, b4);
        return lcd_pixel::PackXrgb(lcd_pixel::Expand4(r4), lcd_pixel::Expand4(g4),
                                   lcd_pixel::Expand4(b4));
    }

    static uint32_t DecodePixel(Sed1356& sed, const uint8_t* vram,
                                uint32_t line, uint32_t x, uint32_t bpp) {
        switch (bpp) {
            case 16u:
                return lcd_pixel::Expand565(static_cast<uint16_t>(sed.VramLoad(line + x * 2u, 2u)));
            case 15u:                          /* §11.1: 5-5-5. */
                return lcd_pixel::Expand555(static_cast<uint16_t>(sed.VramLoad(line + x * 2u, 2u)));
            case 8u:
                return FromLut(sed, vram[sed.VramWrap(line + x)]);
            default: {                         /* 4 bpp: pixel 0 in bits 7:4. */
                const uint8_t b = vram[sed.VramWrap(line + x / 2u)];
                return FromLut(sed, (x & 1u) ? (b & 0xFu) : (b >> 4));
            }
        }
    }

    /* Ink/cursor layer §14: 2-bpp image, pixel n = (A,B) pair packed
       MSB-first (Fig 14-1); 00=color0, 01=color1, 10=transparent,
       11=inverted background (Table 14-2). */
    void ComposeInkCursor(Sed1356& sed, uint32_t* dib, uint32_t host_w,
                          uint32_t cw, uint32_t ch, uint32_t gw, uint32_t gh) {
        const uint32_t mode = sed.LcdInkCursorMode();
        if (mode == 0u || mode == 3u) return;

        const uint32_t base = sed.LcdInkCursorStartByte();
        const uint8_t* vram = sed.VramData();

        uint8_t r5, g6, b5;
        sed.LcdInkColor(0, r5, g6, b5);
        const uint32_t c0 = lcd_pixel::PackXrgb(lcd_pixel::Expand5(r5), lcd_pixel::Expand6(g6),
                                                lcd_pixel::Expand5(b5));
        sed.LcdInkColor(1, r5, g6, b5);
        const uint32_t c1 = lcd_pixel::PackXrgb(lcd_pixel::Expand5(r5), lcd_pixel::Expand6(g6),
                                                lcd_pixel::Expand5(b5));

        /* Cursor: fixed 64x64, 8 words/line; ink: covers the display from
           the top-left, line offset REG[072h]+1 words (§14.1). */
        const bool cursor = (mode == 1u);
        const int32_t ox = cursor ? (sed.LcdCursorXNeg()
                               ? -(int32_t)sed.LcdCursorX()
                               : (int32_t)sed.LcdCursorX()) : 0;
        const int32_t oy = cursor ? (sed.LcdCursorYNeg()
                               ? -(int32_t)sed.LcdCursorY()
                               : (int32_t)sed.LcdCursorY()) : 0;
        const uint32_t img_w = cursor ? 64u : gw;
        const uint32_t img_h = cursor ? 64u : gh;
        const uint32_t line_bytes =
            cursor ? 16u : ((uint32_t)sed.BltReg(0x72) + 1u) * 2u;

        for (uint32_t iy = 0; iy < img_h; ++iy) {
            const int32_t dy = oy + (int32_t)iy;
            if (dy < 0 || (uint32_t)dy >= ch) continue;
            for (uint32_t ix = 0; ix < img_w; ++ix) {
                const int32_t dx = ox + (int32_t)ix;
                if (dx < 0 || (uint32_t)dx >= cw) continue;
                const uint32_t at = sed.VramWrap(base + iy * line_bytes + ix / 4u);
                const uint32_t shift = (3u - (ix & 3u)) * 2u;
                const uint32_t px = (vram[at] >> shift) & 0x3u;
                uint32_t* d = dib + (size_t)dy * host_w + dx;
                switch (px) {
                    case 0u: *d = c0; break;
                    case 1u: *d = c1; break;
                    case 2u: break;                       /* transparent. */
                    case 3u: *d = 0xFF000000u | ~*d; break;
                }
            }
        }
    }

};

}  /* namespace */

REGISTER_SERVICE_AS(Sed1356Renderer, PanelFrameRenderer);
