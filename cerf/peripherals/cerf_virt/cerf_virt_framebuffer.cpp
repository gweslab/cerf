#include "cerf_virt_framebuffer.h"

#include "cerf_virt_addr_map.h"
#include "../../core/cerf_emulator.h"
#include "../../core/device_config.h"
#include "../../core/log.h"

REGISTER_SERVICE(CerfVirtFramebuffer);

bool CerfVirtFramebuffer::ShouldRegister() {
    return emu_.Get<DeviceConfig>().guest_additions;
}

static const uint32_t kOffscreenMultiple = 3u;

uint32_t CerfVirtFramebuffer::ComputeRegionBytes() const {
    uint32_t desired = SizeBytes() * (1u + kOffscreenMultiple);
    if (desired < CerfVirt::kFramebufferMemSize)
        desired = CerfVirt::kFramebufferMemSize;

    const uint32_t window = (CerfVirt::kBaseAddr + CerfVirt::kTotalSize)
                            - CerfVirt::kFramebufferMemBase;
    if (desired > window) {
        LOG(Caution, "[CerfVirtFramebuffer] %ux%u needs %u B FB region, only "
                     "%u B fits below 0xE0000000 (SA1110 zero-bank); raise "
                     "kTotalSize / relocate region in cerf_virt_addr_map.h to "
                     "support this resolution\n",
            width_, height_, desired, window);
        CerfFatalExit(CERF_FATAL_RUNTIME_ERROR);
    }
    return desired;
}

void CerfVirtFramebuffer::OnReady() {
    const auto& cfg = emu_.Get<DeviceConfig>();
    width_  = cfg.board_configurable_screen_width;
    height_ = cfg.board_configurable_screen_height;
    region_bytes_ = ComputeRegionBytes();
    bytes_.assign(region_bytes_, 0);
    LOG(Periph, "[CerfVirtFramebuffer] %ux%u %ubpp stride=%u "
                "fb_size=%u region=%u bytes (offscreen=%u bytes)\n",
        width_, height_, bpp_, Stride(), SizeBytes(),
        region_bytes_, region_bytes_ - SizeBytes());
}
