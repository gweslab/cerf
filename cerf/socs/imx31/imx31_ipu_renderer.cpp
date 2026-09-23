#define NOMINMAX

#include "imx31_ipu.h"

#include "../../boards/board_context.h"
#include "imx31_id.h"
#include "../../core/byte_order.h"
#include "../../core/cerf_emulator.h"
#include "../../core/log.h"
#include "../../cpu/emulated_memory.h"
#include "../../host/panel_frame_renderer.h"
#include "../../lcd/lcd_pixel_expand.h"

#include <cstring>

namespace {

bool IsRgb565(const Imx31Ipu::ChannelFormat& f) {
    return f.pfs == Imx31Ipu::PfsKind::RgbPack
        && f.bpp_bits == 16
        && f.wid[0] == 5 && f.ofs[0] == 0
        && f.wid[1] == 6 && f.ofs[1] == 5
        && f.wid[2] == 5 && f.ofs[2] == 11;
}

class Imx31IpuRenderer : public PanelFrameRenderer {
public:
    using PanelFrameRenderer::PanelFrameRenderer;

    bool ShouldRegister() override {
        auto* bd = emu_.TryGet<BoardContext>();
        return bd && bd->GetSocId() == SocId::Imx31;
    }

    void PresentedSize(uint32_t& w, uint32_t& h) override {
        auto& ipu = emu_.Get<Imx31Ipu>();
        w = ipu.GetGuestW();
        h = ipu.GetGuestH();
    }

    bool HasFrame() override {
        auto& ipu = emu_.Get<Imx31Ipu>();
        const bool enabled = ipu.IsEnabled();
        if (!enabled)             return false;
        if (latch_.Latched())     return true;
        const uint32_t fb_pa = ipu.GetSdcBgFbPa();
        const Imx31Ipu::ChannelFormat fmt = ipu.GetSdcBgFormat();
        const uint32_t guest_w = ipu.GetGuestW();
        const uint32_t guest_h = ipu.GetGuestH();
        if (fb_pa == 0 || guest_w <= 1 || guest_h <= 1) return false;
        if (fmt.pfs == Imx31Ipu::PfsKind::Unknown || fmt.bpp_bits == 0) return false;
        const size_t pixel_bytes = (fmt.bpp_bits + 7u) / 8u;
        const size_t fb_bytes = (size_t)guest_w * (size_t)guest_h * pixel_bytes;
        const bool got = latch_.ProbeAndLatch(emu_.Get<EmulatedMemory>(),
                                    fb_pa, fb_bytes);
        return got;
    }

    void RenderInto(uint32_t* dib_bgra32,
                    uint32_t  host_w,
                    uint32_t  host_h) override {
        auto& ipu = emu_.Get<Imx31Ipu>();
        const uint32_t fb_pa = ipu.GetSdcBgFbPa();
        const Imx31Ipu::ChannelFormat fmt = ipu.GetSdcBgFormat();
        /* Framebuffer geometry = SDC BG channel descriptor (FW frame width, SL
           stride bytes) - the layout the IPU DMA fetches - NOT the SDC panel
           timing SCREEN_WIDTH/HEIGHT: reading rows at the panel width skews each
           row by (screen_w-fw)*2 B. MCIMX31RM §44.4: W0[119:108]=FW, W1[80:67]=SL. */
        const uint32_t fb_w  = fmt.fw;
        const uint32_t fb_h  = fmt.fh;
        const uint32_t pitch = fmt.stride;

        std::memset(dib_bgra32, 0, (size_t)host_w * host_h * 4u);

        const uint32_t copy_w = (fb_w < host_w) ? fb_w : host_w;
        const uint32_t copy_h = (fb_h < host_h) ? fb_h : host_h;
        if (copy_w == 0 || copy_h == 0) return;

        const uint8_t* src_base =
            emu_.Get<EmulatedMemory>().TryTranslate(fb_pa);
        if (!src_base) return;

        if (!IsRgb565(fmt)) {
            LOG(Periph, "[IPU] unsupported SDC bg format pfs=%u bpp=%u "
                        "wid=%u/%u/%u/%u ofs=%u/%u/%u/%u - renderer halt\n",
                (unsigned)fmt.pfs, fmt.bpp_bits,
                fmt.wid[0], fmt.wid[1], fmt.wid[2], fmt.wid[3],
                fmt.ofs[0], fmt.ofs[1], fmt.ofs[2], fmt.ofs[3]);
            CerfFatalExit(CERF_FATAL_RUNTIME_ERROR);
        }

        for (uint32_t y = 0; y < copy_h; ++y) {
            const uint8_t* src_row = src_base + (size_t)y * pitch;
            uint32_t* dst_row = dib_bgra32 + (size_t)y * host_w;
            for (uint32_t x = 0; x < copy_w; ++x)
                dst_row[x] = lcd_pixel::Expand565(cerf::le::U16(src_row, (size_t)x * 2u));
        }
    }

    std::optional<FbLayout> GetFbLayout() override {
        auto& ipu = emu_.Get<Imx31Ipu>();
        const uint32_t pa = ipu.GetSdcBgFbPa();
        if (pa == 0) return std::nullopt;
        const Imx31Ipu::ChannelFormat fmt = ipu.GetSdcBgFormat();
        return FbLayout{ pa, fmt.stride, fmt.bpp_bits, IsRgb565(fmt) };
    }
};

}  /* namespace */

REGISTER_SERVICE_AS(Imx31IpuRenderer, PanelFrameRenderer);
