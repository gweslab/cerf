#define NOMINMAX
#include <windows.h>

#include "cerf_virt_framebuffer.h"

#include "cerf_virt_addr_map.h"
#include "../../boards/board_context.h"
#include "../../core/cerf_emulator.h"
#include "../../core/device_config.h"
#include "../../core/log.h"
#include "../../socs/guest_cpu_reset.h"
#include "../../state/state_stream.h"

#include <cstring>

REGISTER_SERVICE(CerfVirtFramebuffer);

bool CerfVirtFramebuffer::ShouldRegister() {
    return emu_.Get<DeviceConfig>().guest_additions;
}

static const uint32_t kOffscreenMultiple = 3u;

namespace {
struct MaxMonitorDims { uint32_t w = 0; uint32_t h = 0; };

BOOL CALLBACK AccumulateMaxMonitor(HMONITOR, HDC, LPRECT rc, LPARAM lp) {
    auto* m = reinterpret_cast<MaxMonitorDims*>(lp);
    const uint32_t w = (uint32_t)(rc->right - rc->left);
    const uint32_t h = (uint32_t)(rc->bottom - rc->top);
    if ((uint64_t)w * h > (uint64_t)m->w * m->h) { m->w = w; m->h = h; }
    return TRUE;
}
}

uint32_t CerfVirtFramebuffer::ComputeRegionBytes() {

    const uint32_t bytes_per_px = bpp_ >> 3u;
    uint32_t max_primary = SizeBytes();
    MaxMonitorDims mon;
    EnumDisplayMonitors(nullptr, nullptr, &AccumulateMaxMonitor, (LPARAM)&mon);
    if (mon.w == 0 || mon.h == 0) {
        mon.w = (uint32_t)GetSystemMetrics(SM_CXSCREEN);
        mon.h = (uint32_t)GetSystemMetrics(SM_CYSCREEN);
    }
    const uint32_t mon_primary = mon.w * mon.h * bytes_per_px;
    if (mon_primary > max_primary) max_primary = mon_primary;

    primary_reserve_ = max_primary;
    uint32_t desired = max_primary * (1u + kOffscreenMultiple);
    if (desired < CerfVirt::kFramebufferMemSize)
        desired = CerfVirt::kFramebufferMemSize;

    const uint32_t window = CerfVirt::kTotalSize - CerfVirt::kFramebufferMemOffset;
    if (desired > window) {
        LOG(Caution, "[CerfVirtFramebuffer] %ux%u needs %u B FB region, only "
                     "%u B fits in the cerf_virt window; raise kTotalSize in "
                     "cerf_virt_addr_map.h to support this resolution\n",
            width_, height_, desired, window);
        CerfFatalExit(CERF_FATAL_RUNTIME_ERROR);
    }
    return desired;
}

uint32_t CerfVirtFramebuffer::MemBasePa() const {
    return emu_.Get<BoardContext>().GuestAdditionsWindowBase()
         + CerfVirt::kFramebufferMemOffset;
}

void CerfVirtFramebuffer::OnReady() {
    const auto& cfg = emu_.Get<DeviceConfig>();
    width_  = cfg.board_configurable_screen_width;
    height_ = cfg.board_configurable_screen_height;
    bpp_    = emu_.Get<BoardContext>().ResolveGuestAdditionsColorDepth();
    region_bytes_ = ComputeRegionBytes();
    bytes_.assign(region_bytes_, 0);
    emu_.Get<GuestCpuReset>().RegisterResetListener([this](ResetLineKind) {
        ReapplyConfiguredDepth();
        if (!emu_.Get<GuestCpuReset>().DeliveredResetWasResume()) ClearContent();
    });
    LOG(Periph, "[CerfVirtFramebuffer] %ux%u %ubpp stride=%u "
                "fb_size=%u region=%u bytes (offscreen=%u bytes)\n",
        width_, height_, bpp_, Stride(), SizeBytes(),
        region_bytes_, region_bytes_ - SizeBytes());
}

void CerfVirtFramebuffer::SaveState(StateWriter& w) {
    w.Write("bpp", bpp_);
    w.Write("width", width_);
    w.Write("height", height_);
    w.Write<uint8_t>("any_write", any_write_ ? 1u : 0u);
    for (uint32_t i = 0; i < 256u; ++i) w.Write("palette", palette_[i]);
    w.WriteBytes("bytes", bytes_.data(), bytes_.size());
}

void CerfVirtFramebuffer::RestoreState(StateReader& r) {
    uint32_t bpp = 0;
    r.Read("bpp", bpp);
    if (bpp != bpp_)
        r.Reject("the guest display ran at %u bpp, this machine is at %u bpp", bpp, bpp_);
    uint32_t w = 0, h = 0;
    r.Read("width", w);
    r.Read("height", h);
    width_  = w;
    height_ = h;
    uint8_t aw = 0;
    r.Read("any_write", aw);
    any_write_ = (aw != 0);
    for (uint32_t i = 0; i < 256u; ++i) r.Read("palette", palette_[i]);
    r.ReadBytes("bytes", bytes_.data(), bytes_.size());
}

void CerfVirtFramebuffer::ClearContent() {
    if (!bytes_.empty()) std::memset(bytes_.data(), 0, bytes_.size());
    any_write_ = false;
}

void CerfVirtFramebuffer::ReapplyConfiguredDepth() {
    const uint32_t want = emu_.Get<BoardContext>().ResolveGuestAdditionsColorDepth();
    if (want == bpp_) return;
    const uint32_t was = bpp_;
    bpp_ = want;
    const uint32_t need = ComputeRegionBytes();
    if (need > region_bytes_) {
        region_bytes_ = need;
        bytes_.assign(region_bytes_, 0);
    }
    LOG(Periph, "[CerfVirtFramebuffer] colour depth %ubpp -> %ubpp "
                "stride=%u region=%u bytes\n", was, bpp_, Stride(), region_bytes_);
}

void CerfVirtFramebuffer::ApplyGuestMode(uint32_t w, uint32_t h) {
    if (w == 0 || h == 0) return;
    const uint32_t need = h * (w * (bpp_ >> 3u));
    if (need > primary_reserve_) {
        LOG(Caution, "[CerfVirtFramebuffer] guest applied %ux%u (%u B) exceeds "
                     "primary reserve %u B; ignoring\n", w, h, need, primary_reserve_);
        return;
    }
    width_  = w;
    height_ = h;
    LOG(Periph, "[CerfVirtFramebuffer] guest re-moded to %ux%u stride=%u\n",
        width_, height_, Stride());
}
