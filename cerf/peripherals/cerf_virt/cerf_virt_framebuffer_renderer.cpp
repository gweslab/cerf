#define NOMINMAX

#include "cerf_virt_framebuffer.h"

#include "../../core/byte_order.h"
#include "../../core/cerf_emulator.h"
#include "../../core/device_config.h"
#include "../../host/guest_additions_frame_renderer.h"
#include "../../lcd/lcd_pixel_expand.h"

#include <algorithm>
#include <cstring>

namespace {

class CerfVirtFramebufferRenderer : public GuestAdditionsFrameRenderer {
public:
    using GuestAdditionsFrameRenderer::GuestAdditionsFrameRenderer;

    bool ShouldRegister() override {
        return emu_.Get<DeviceConfig>().guest_additions;
    }

    void PresentedSize(uint32_t& w, uint32_t& h) override {
        auto& fb = emu_.Get<CerfVirtFramebuffer>();
        w = fb.Width();
        h = fb.Height();
    }

    bool HasFrame() override {
        auto& fb = emu_.Get<CerfVirtFramebuffer>();
        if (!fb.HasContent()) return false;
        if (latch_.Latched()) return true;
        const size_t bytes = fb.SizeBytes();
        if (bytes == 0 || bytes > fb.Capacity()) return false;
        return latch_.ProbeAndLatch(fb.Bytes(), bytes);
    }

    void RearmContentLatch() override {
        GuestAdditionsFrameRenderer::RearmContentLatch();
        emu_.Get<CerfVirtFramebuffer>().ClearContentEdge();
    }

    void RenderInto(uint32_t* dib_bgra32,
                    uint32_t  host_w,
                    uint32_t  host_h) override {
        auto& fb = emu_.Get<CerfVirtFramebuffer>();
        const uint32_t guest_w = fb.Width();
        const uint32_t guest_h = fb.Height();
        const uint8_t* src = fb.Bytes();

        std::memset(dib_bgra32, 0,
                    static_cast<size_t>(host_w) * host_h * 4u);

        const uint32_t copy_w = std::min(guest_w, host_w);
        const uint32_t copy_h = std::min(guest_h, host_h);
        if (copy_w == 0 || copy_h == 0) return;

        const uint32_t guest_stride = fb.Stride();
        const uint32_t bpp = fb.Bpp();
        for (uint32_t y = 0; y < copy_h; ++y) {
            const uint8_t* src_row = src + static_cast<size_t>(y) * guest_stride;
            uint32_t* dst_row = dib_bgra32 + static_cast<size_t>(y) * host_w;
            if (bpp == 32u) {
                std::memcpy(dst_row, src_row, static_cast<size_t>(copy_w) * 4u);
            } else if (bpp == 8u) {
                const uint32_t* pal = fb.Palette();
                for (uint32_t x = 0; x < copy_w; ++x)
                    dst_row[x] = 0xFF000000u | pal[src_row[x]];
            } else if (bpp == 16u) {
                for (uint32_t x = 0; x < copy_w; ++x)
                    dst_row[x] = lcd_pixel::Expand565(
                        cerf::le::U16(src_row, static_cast<size_t>(x) * 2u));
            } else if (bpp == 24u) {
                for (uint32_t x = 0; x < copy_w; ++x) {
                    dst_row[x] = 0xFF000000u
                               | cerf::le::U24(src_row, static_cast<size_t>(x) * 3u);
                }
            }
        }
    }
};

REGISTER_SERVICE_AS(CerfVirtFramebufferRenderer, GuestAdditionsFrameRenderer);

}
