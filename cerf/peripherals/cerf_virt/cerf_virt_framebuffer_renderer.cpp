#define NOMINMAX

#include "cerf_virt_framebuffer.h"

#include "../../core/cerf_emulator.h"
#include "../../core/device_config.h"
#include "../../host/frame_renderer.h"

#include <algorithm>
#include <cstring>

namespace {

class CerfVirtFramebufferRenderer : public FrameRenderer {
public:
    using FrameRenderer::FrameRenderer;

    bool ShouldRegister() override {
        return emu_.Get<DeviceConfig>().guest_additions;
    }

    bool HasFrame() override {
        return emu_.Get<CerfVirtFramebuffer>().HasContent();
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
        for (uint32_t y = 0; y < copy_h; ++y) {
            const uint32_t* src_row = reinterpret_cast<const uint32_t*>(
                src + static_cast<size_t>(y) * guest_stride);
            uint32_t* dst_row =
                dib_bgra32 + static_cast<size_t>(y) * host_w;
            std::memcpy(dst_row, src_row,
                        static_cast<size_t>(copy_w) * 4u);
        }
    }
};

REGISTER_SERVICE_AS(CerfVirtFramebufferRenderer, FrameRenderer);

}  /* namespace */
