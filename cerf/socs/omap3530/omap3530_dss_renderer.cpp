#define NOMINMAX

#include "omap3530_dss.h"

#include "../../boards/board_context.h"
#include "omap3530_id.h"
#include "../../core/byte_order.h"
#include "../../core/cerf_emulator.h"
#include "../../core/log.h"
#include "../../cpu/emulated_memory.h"
#include "../../host/panel_frame_renderer.h"
#include "../../lcd/lcd_pixel_expand.h"

#include <cstdint>
#include <cstring>

namespace {

constexpr uint32_t kFmtRgb16 = 0x6u;

class Omap3530DssRenderer : public PanelFrameRenderer {
public:
    using PanelFrameRenderer::PanelFrameRenderer;

    bool ShouldRegister() override {
        auto* bd = emu_.TryGet<BoardContext>();
        return bd && bd->GetSocId() == SocId::Omap3530;
    }

    void PresentedSize(uint32_t& w, uint32_t& h) override {
        auto& dss = emu_.Get<Omap3530Dss>();
        w = dss.GetGuestW();
        h = dss.GetGuestH();
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
                                    fb_pa, fb_bytes);
    }

    void RenderInto(uint32_t* dib_bgra32,
                    uint32_t  host_w,
                    uint32_t  host_h) override {
        std::memset(dib_bgra32, 0, (size_t)host_w * host_h * 4u);

        auto& dss = emu_.Get<Omap3530Dss>();
        const uint32_t format = dss.GetGfxFormat();
        if (format != kFmtRgb16) {
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

        for (uint32_t y = 0; y < copy_h; ++y) {
            const uint8_t* src_row = src_base + (size_t)y * guest_w * 2u;
            uint32_t* dst_row = dib_bgra32 + (size_t)y * host_w;
            for (uint32_t x = 0; x < copy_w; ++x)
                dst_row[x] = lcd_pixel::Expand565(cerf::le::U16(src_row, (size_t)x * 2u));
        }
    }

    std::optional<FbLayout> GetFbLayout() override {
        auto& dss = emu_.Get<Omap3530Dss>();
        const uint32_t pa = dss.GetFbPa();
        if (pa == 0) return std::nullopt;
        return FbLayout{ pa, dss.GetGuestW() * 2u, 16u, true };
    }

private:
};

}  /* namespace */

REGISTER_SERVICE_AS(Omap3530DssRenderer, PanelFrameRenderer);
