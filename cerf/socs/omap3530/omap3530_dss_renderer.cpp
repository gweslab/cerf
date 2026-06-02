#define NOMINMAX

#include "omap3530_dss.h"

#include "../../boards/board_detector.h"
#include "../../core/cerf_emulator.h"
#include "../../core/device_config.h"
#include "../../core/log.h"
#include "../../cpu/emulated_memory.h"
#include "../../host/frame_renderer.h"
#include "../../lcd/lcd_content_latch.h"

#include <cstdint>
#include <cstring>

namespace {

constexpr uint32_t kFmtRgb16 = 0x6u;

constexpr size_t kContentProbeStride = 251;

class Omap3530DssRenderer : public FrameRenderer {
public:
    using FrameRenderer::FrameRenderer;

    bool ShouldRegister() override {
        if (emu_.Get<DeviceConfig>().guest_additions) return false;
        auto* bd = emu_.TryGet<BoardDetector>();
        return bd && bd->GetSoc() == SocFamily::OMAP3530;
    }

    bool HasFrame() override {
        auto& dss = emu_.Get<Omap3530Dss>();
        if (!dss.IsScanning()) return false;
        if (latch_.Latched())  return true;
        const uint32_t fb_pa = dss.GetFbPa();
        const uint32_t w     = dss.GetGuestW();
        const uint32_t h     = dss.GetGuestH();
        if (fb_pa == 0 || w == 0 || h == 0) return false;
        const size_t fb_bytes = (size_t)w * (size_t)h * 2u;  /* RGB16 */
        return latch_.ProbeAndLatch(emu_.Get<EmulatedMemory>(),
                                    fb_pa, fb_bytes,
                                    kContentProbeStride);
    }

    void RenderInto(uint32_t* dib_bgra32,
                    uint32_t  host_w,
                    uint32_t  host_h) override {
        std::memset(dib_bgra32, 0, (size_t)host_w * host_h * 4u);

        auto& dss = emu_.Get<Omap3530Dss>();
        const uint32_t format = dss.GetGfxFormat();
        if (format != kFmtRgb16) {
            /* lcd_vga.c:343 pins DEFAULT_PIXELTYPE = DISPC_PIXELFORMAT_RGB16
               for every BSP_DVI_* config of this BSP. Halt loudly on any
               other format until proven by a guest write pattern; guessing
               byte order corrupts the entire frame silently. */
            LOG(Caution, "Omap3530DssRenderer: GFXFORMAT=0x%X not "
                    "modelled (only RGB16=0x6 verified from BSP). "
                    "Halting.\n", format);
            CerfFatalExit(CERF_FATAL_RUNTIME_ERROR);
        }

        const uint32_t fb_pa   = dss.GetFbPa();
        const uint32_t guest_w = dss.GetGuestW();
        const uint32_t guest_h = dss.GetGuestH();
        if (fb_pa == 0 || guest_w == 0 || guest_h == 0) return;

        const uint8_t* src_base =
            emu_.Get<EmulatedMemory>().TryTranslate(fb_pa);
        if (!src_base) return;

        const uint32_t copy_w = (guest_w < host_w) ? guest_w : host_w;
        const uint32_t copy_h = (guest_h < host_h) ? guest_h : host_h;
        if (copy_w == 0 || copy_h == 0) return;

        /* 5:6:5 → BGRA8888 with top-bit replication so 0x1F → 0xFF
           and 0x3F → 0xFF (clean 8-bit expansion). */
        for (uint32_t y = 0; y < copy_h; ++y) {
            const uint16_t* src_row = reinterpret_cast<const uint16_t*>(
                src_base + (size_t)y * guest_w * 2u);
            uint32_t* dst_row = dib_bgra32 + (size_t)y * host_w;
            for (uint32_t x = 0; x < copy_w; ++x) {
                const uint16_t px = src_row[x];
                const uint8_t r5 = (px >> 11) & 0x1Fu;
                const uint8_t g6 = (px >>  5) & 0x3Fu;
                const uint8_t b5 =  px        & 0x1Fu;
                const uint8_t r  = (uint8_t)((r5 << 3) | (r5 >> 2));
                const uint8_t g  = (uint8_t)((g6 << 2) | (g6 >> 4));
                const uint8_t b  = (uint8_t)((b5 << 3) | (b5 >> 2));
                dst_row[x] = 0xFF000000u | ((uint32_t)r << 16)
                                         | ((uint32_t)g <<  8)
                                         |  (uint32_t)b;
            }
        }
    }

    std::optional<FbLayout> GetFbLayout() override {
        auto& dss = emu_.Get<Omap3530Dss>();
        const uint32_t pa = dss.GetFbPa();
        if (pa == 0) return std::nullopt;
        return FbLayout{ pa, dss.GetGuestW() * 2u, 16u, true };
    }

private:
    LcdContentLatch latch_;
};

}  /* namespace */

REGISTER_SERVICE_AS(Omap3530DssRenderer, FrameRenderer);
