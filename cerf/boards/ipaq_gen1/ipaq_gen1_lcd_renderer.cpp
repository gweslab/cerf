#define NOMINMAX

#include "../../socs/sa11xx/sa11xx_lcd.h"

#include "../board_context.h"
#include "../../core/cerf_emulator.h"
#include "../../core/log.h"
#include "../../cpu/emulated_memory.h"
#include "../../host/panel_frame_renderer.h"

#include <algorithm>
#include <cstring>

namespace {

/* SA-1110 §11.7.1.2: in active TFT 16-bpp mode (PBS=2, PAS=1), the
   frame buffer begins with a 32-byte dummy palette buffer that the
   LCD controller loads but does not use, followed by 16-bit pixel
   data laid out per Figure 11-9: R[15:11] G[10:5] B[4:0]. */

constexpr uint32_t kDummyPaletteBytes  = 32;
constexpr uint32_t kBytesPerGuestPixel = 2;
constexpr size_t   kContentProbeStride = 251;

/* Panel is 320x240: Linux arch/arm/mach-sa1100/h3600.c h3600_lcd_info and
   h3100.c h3100_lcd_info, both .xres = 320, .yres = 240. */
constexpr uint32_t kPanelLines = 240;

/* SA-1110 §11.7.1.5 Table 11-7: dither value -> pixel-ON duty. The H31xx
   STN glass darkens when driven (Linux h3100_lcd_info: cmap_inverse=1;
   the ROM's ddi.dll programs an identity hw palette relying on it), so
   intensity = duty complement - an ascending table inverts the screen. */
constexpr uint8_t kMonoGray[16] = { 255, 227, 204, 187, 170, 153, 142, 127,
                                    113, 102, 85, 68, 51, 28, 0, 0 };

/* PBS, palette entry 0 bits 13:12 (devman p.11-19): 00=4bpp/32-byte
   palette, 01=8bpp/512-byte palette. The manual misprints the 4bpp row
   as "0x", which would overlap the "01 - 8 bits" row; 01 is 8 bpp. */
struct MonoLayout {
    uint32_t data_off;
    uint32_t bits_per_px;
    uint32_t pal_entries;
};

class IpaqGen1LcdRenderer : public PanelFrameRenderer {
public:
    using PanelFrameRenderer::PanelFrameRenderer;

    bool ShouldRegister() override {
        auto* bd = emu_.TryGet<BoardContext>();
        return bd && bd->GetBoard() == Board::IpaqGen1;
    }

    void PresentedSize(uint32_t& w, uint32_t& h) override {
        w = PanelH();
        h = emu_.Get<Sa11xxLcd>().GetGuestW();
    }

    bool HasFrame() override {
        auto& lcd = emu_.Get<Sa11xxLcd>();
        if (!lcd.IsEnabled())              return false;
        if (latch_.Latched())              return true;
        const uint32_t fb_pa   = lcd.GetFbPa();
        const uint32_t guest_w = lcd.GetGuestW();
        const uint32_t guest_h = PanelH();
        if (fb_pa == 0 || guest_w == 0 || guest_h == 0) return false;

        uint32_t data_off    = kDummyPaletteBytes;
        size_t   pixel_bytes = (size_t)guest_w * (size_t)guest_h
                             * (size_t)kBytesPerGuestPixel;
        if (!lcd.IsColor()) {
            const uint8_t* fb_base =
                emu_.Get<EmulatedMemory>().TryTranslate(fb_pa);
            if (!fb_base) return false;
            const MonoLayout ml = ResolveMonoLayout(fb_base);
            data_off    = ml.data_off;
            pixel_bytes = (size_t)guest_w * (size_t)guest_h
                        * (size_t)ml.bits_per_px / 8u;
        }
        return latch_.ProbeAndLatch(emu_.Get<EmulatedMemory>(),
                                    fb_pa + data_off,
                                    pixel_bytes,
                                    kContentProbeStride);
    }

    void RenderInto(uint32_t* dib_bgra32,
                    uint32_t  host_w,
                    uint32_t  host_h) override {
        auto& lcd = emu_.Get<Sa11xxLcd>();
        const uint32_t fb_pa   = lcd.GetFbPa();
        const uint32_t guest_w = lcd.GetGuestW();
        const uint32_t guest_h = PanelH();

        std::memset(dib_bgra32, 0, (size_t)host_w * host_h * 4u);
        if (guest_w == 0 || guest_h == 0) return;

        const uint8_t* fb_base = emu_.Get<EmulatedMemory>().TryTranslate(fb_pa);
        if (!fb_base) return;

        if (lcd.IsColor()) {
            RenderColorInto(dib_bgra32, host_w, host_h,
                            fb_base, guest_w, guest_h);
        } else {
            RenderMonoInto(dib_bgra32, host_w, host_h,
                           fb_base, guest_w, guest_h);
        }
    }

    std::optional<FbLayout> GetFbLayout() override {
        auto& lcd = emu_.Get<Sa11xxLcd>();
        const uint32_t pa = lcd.GetFbPa();
        if (pa == 0) return std::nullopt;
        if (!lcd.IsColor()) {
            const uint8_t* fb_base =
                emu_.Get<EmulatedMemory>().TryTranslate(pa);
            if (!fb_base) return std::nullopt;
            const MonoLayout ml = ResolveMonoLayout(fb_base);
            return FbLayout{ pa + ml.data_off,
                             lcd.GetGuestW() * ml.bits_per_px / 8u,
                             ml.bits_per_px, false };
        }
        /* Pixel data follows the 32-byte dummy palette buffer (§11.7.1.2). */
        return FbLayout{ pa + kDummyPaletteBytes,
                         lcd.GetGuestW() * kBytesPerGuestPixel, 16u, true };
    }

private:
    uint32_t PanelH() {
        return std::min(emu_.Get<Sa11xxLcd>().GetGuestH(), kPanelLines);
    }

    MonoLayout ResolveMonoLayout(const uint8_t* fb_base) {
        const uint16_t entry0 =
            (uint16_t)(fb_base[0] | ((uint16_t)fb_base[1] << 8));
        const uint32_t pbs = (entry0 >> 12) & 0x3u;
        switch (pbs) {
            case 0: return MonoLayout{ 0x20u,  4u, 16u  };
            case 1: return MonoLayout{ 0x200u, 8u, 256u };
            default: break;
        }
        /* PBS=10 bypasses the palette with 12-bit RGB pixels (p.11-19) -
           contradicts CMS=1's 4-bit gray palette path; PBS=11 reserved.
           Neither has defined mono behavior. */
        LOG(Lcd, "IpaqGen1LcdRenderer: FATAL mono frame with PBS=%u "
                 "(palette entry0=0x%04X) - undefined combination\n",
            pbs, entry0);
        CerfFatalExit(CERF_FATAL_RUNTIME_ERROR);
    }

    void RenderColorInto(uint32_t* dib_bgra32,
                         uint32_t host_w, uint32_t host_h,
                         const uint8_t* fb_base,
                         uint32_t guest_w, uint32_t guest_h) {
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

    void RenderMonoInto(uint32_t* dib_bgra32,
                        uint32_t host_w, uint32_t host_h,
                        const uint8_t* fb_base,
                        uint32_t guest_w, uint32_t guest_h) {
        const MonoLayout ml = ResolveMonoLayout(fb_base);

        /* §11.7.1: the palette is re-transferred from the frame buffer
           every frame; mirror that by rebuilding the LUT per render. */
        uint32_t lut[256];
        for (uint32_t i = 0; i < ml.pal_entries; ++i) {
            const uint16_t e =
                (uint16_t)(fb_base[i * 2] | ((uint16_t)fb_base[i * 2 + 1] << 8));
            const uint8_t  g = kMonoGray[e & 0xFu];
            lut[i] = 0xFF000000u | ((uint32_t)g << 16)
                                 | ((uint32_t)g <<  8)
                                 |  (uint32_t)g;
        }
        if (!mono_palette_logged_) {
            mono_palette_logged_ = true;
            LOG(Lcd, "IpaqGen1LcdRenderer: mono frame %ubpp, palette "
                     "%04X %04X %04X %04X %04X %04X %04X %04X "
                     "%04X %04X %04X %04X %04X %04X %04X %04X\n",
                ml.bits_per_px,
                fb_base[0]  | (fb_base[1]  << 8), fb_base[2]  | (fb_base[3]  << 8),
                fb_base[4]  | (fb_base[5]  << 8), fb_base[6]  | (fb_base[7]  << 8),
                fb_base[8]  | (fb_base[9]  << 8), fb_base[10] | (fb_base[11] << 8),
                fb_base[12] | (fb_base[13] << 8), fb_base[14] | (fb_base[15] << 8),
                fb_base[16] | (fb_base[17] << 8), fb_base[18] | (fb_base[19] << 8),
                fb_base[20] | (fb_base[21] << 8), fb_base[22] | (fb_base[23] << 8),
                fb_base[24] | (fb_base[25] << 8), fb_base[26] | (fb_base[27] << 8),
                fb_base[28] | (fb_base[29] << 8), fb_base[30] | (fb_base[31] << 8));
        }

        /* H31xx glass is mounted 180° relative to H36xx glass: the LCD
           controller has no scan-direction field (§11.7.3), and the H3100
           mono driver shipped displaying upright, so mono frames rotate
           90° CW where color rotates 90° CCW. */
        const uint8_t* data = fb_base + ml.data_off;
        const uint32_t copy_w = (host_w < guest_h) ? host_w : guest_h;
        const uint32_t copy_h = (host_h < guest_w) ? host_h : guest_w;
        for (uint32_t y_dst = 0; y_dst < copy_h; ++y_dst) {
            const uint32_t x_src = y_dst;
            uint32_t* dst_row = dib_bgra32 + (size_t)y_dst * host_w;
            for (uint32_t x_dst = 0; x_dst < copy_w; ++x_dst) {
                const uint32_t y_src = guest_h - 1u - x_dst;
                const size_t   idx  = (size_t)y_src * guest_w + x_src;
                uint32_t v;
                if (ml.bits_per_px == 4u) {
                    /* Fig 11-4 (little endian): pixel 0 in bits 3:0,
                       pixel 1 in bits 7:4. */
                    const uint8_t b = data[idx >> 1];
                    v = (idx & 1u) ? (uint32_t)(b >> 4) : (uint32_t)(b & 0xFu);
                } else {
                    v = data[idx];
                }
                dst_row[x_dst] = lut[v];
            }
        }
    }

    bool            mono_palette_logged_ = false;
};

}  /* namespace */

REGISTER_SERVICE_AS(IpaqGen1LcdRenderer, PanelFrameRenderer);
