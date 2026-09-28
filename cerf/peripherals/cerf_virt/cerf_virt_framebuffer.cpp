#define NOMINMAX
#include <windows.h>

#include "cerf_virt_framebuffer.h"

#include "cerf_virt_addr_map.h"
#include "../../boards/board_context.h"
#include "../../core/cerf_emulator.h"
#include "../../core/device_config.h"
#include "../../core/fatal.h"
#include "../../core/log.h"
#include "../../host/hw_screen.h"
#include "../../socs/guest_cpu_reset.h"
#include "../../state/state_stream.h"

#include <cstdio>
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

uint32_t CerfVirtFramebuffer::MaxPrimaryBytes() const {
    const uint32_t bytes_per_px = bpp_ >> 3u;
    MaxMonitorDims mon;
    EnumDisplayMonitors(nullptr, nullptr, &AccumulateMaxMonitor, (LPARAM)&mon);
    if (mon.w == 0 || mon.h == 0) {
        mon.w = (uint32_t)GetSystemMetrics(SM_CXSCREEN);
        mon.h = (uint32_t)GetSystemMetrics(SM_CYSCREEN);
    }
    const uint32_t mon_primary = mon.w * mon.h * bytes_per_px;
    const uint32_t configured  = SizeBytes();
    return (mon_primary > configured) ? mon_primary : configured;
}

uint32_t CerfVirtFramebuffer::ComputeRegionBytes() const {
    const uint32_t window_size = emu_.Get<BoardContext>().GuestAdditionsWindowSize();
    if (window_size <= CerfVirt::kFramebufferMemOffset) {
        emu_.Get<Fatal>().Die("CerfVirtFramebuffer: board GA window 0x%08X B ends before "
                              "the FB region offset 0x%08X", window_size,
                              CerfVirt::kFramebufferMemOffset);
    }
    const uint32_t window = window_size - CerfVirt::kFramebufferMemOffset;
    uint32_t desired = MaxPrimaryBytes() * (1u + kOffscreenMultiple);
    if (desired < CerfVirt::kFramebufferMemSize)
        desired = CerfVirt::kFramebufferMemSize;
    if (desired > window) {
        LOG(Periph, "[CerfVirtFramebuffer] FB region %u B capped to the %u B left "
                    "in the board GA window\n", desired, window);
        desired = window;
    }
    return desired;
}

uint64_t CerfVirtFramebuffer::PrimaryBytesAt(uint32_t bpp) const {
    return uint64_t{height_} * width_ * (bpp >> 3u);
}

void CerfVirtFramebuffer::ReservePrimary() {
    if (PrimaryBytesAt(bpp_) > region_bytes_) {
        LOG(Caution, "[CerfVirtFramebuffer] %ux%u at %ubpp needs %llu B, the FB "
                     "region of this board holds %u B\n",
            width_, height_, bpp_, (unsigned long long)PrimaryBytesAt(bpp_), region_bytes_);
        CerfFatalExit(CERF_FATAL_USER_ERROR);
    }
    const uint32_t max_primary = MaxPrimaryBytes();
    if (max_primary > region_bytes_) {
        LOG(Periph, "[CerfVirtFramebuffer] primary reserve %u B capped to the "
                    "%u B FB region\n", max_primary, region_bytes_);
        primary_reserve_ = region_bytes_;
        return;
    }
    primary_reserve_ = max_primary;
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
    ReservePrimary();
    bytes_.assign(region_bytes_, 0);
    emu_.Get<GuestCpuReset>().RegisterResetListener([this](ResetLineKind) {
        ReapplyConfiguredDepth();
        if (!emu_.Get<GuestCpuReset>().DeliveredResetWasResume()) ClearContent();
    });
    LOG(Periph, "[CerfVirtFramebuffer] %ux%u %ubpp stride=%u "
                "fb_size=%u region=%u bytes (offscreen=%u bytes)\n",
        width_, height_, bpp_, Stride(), SizeBytes(),
        region_bytes_, region_bytes_ - primary_reserve_);
}

void CerfVirtFramebuffer::SaveState(StateWriter& w) {
    w.Write("bpp", bpp_);
    w.Write("width", width_);
    w.Write("height", height_);
    w.Write("primary_reserve", primary_reserve_);
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
    uint32_t reserve = 0;
    r.Read("primary_reserve", reserve);
    if (w == 0 || h == 0 || reserve > region_bytes_ || PrimaryBytesAt(bpp_) > reserve)
        r.Reject("the guest display reserved %u B for a %ux%u primary in a %u B region",
                 reserve, w, h, region_bytes_);
    primary_reserve_ = reserve;
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
    if (PrimaryBytesAt(want) > region_bytes_) {
        char msg[192];
        snprintf(msg, sizeof(msg), "Colour depth %u bpp at %ux%u needs %llu B; this "
                 "board's display memory holds %u B. Staying at %u bpp.",
                 want, width_, height_, (unsigned long long)PrimaryBytesAt(want),
                 region_bytes_, bpp_);
        LOG(Caution, "[CerfVirtFramebuffer] %s\n", msg);
        emu_.Get<HwScreen>().AddLine(msg);
        return;
    }
    const uint32_t was = bpp_;
    bpp_ = want;
    ReservePrimary();
    LOG(Periph, "[CerfVirtFramebuffer] colour depth %ubpp -> %ubpp "
                "stride=%u region=%u bytes primary reserve=%u bytes\n",
        was, bpp_, Stride(), region_bytes_, primary_reserve_);
}

void CerfVirtFramebuffer::ApplyGuestMode(uint32_t w, uint32_t h) {
    if (w == 0 || h == 0) return;
    const uint64_t need = uint64_t{h} * w * (bpp_ >> 3u);
    if (need > primary_reserve_) {
        LOG(Caution, "[CerfVirtFramebuffer] guest applied %ux%u (%llu B) exceeds "
                     "primary reserve %u B; ignoring\n", w, h, (unsigned long long)need,
            primary_reserve_);
        return;
    }
    width_  = w;
    height_ = h;
    LOG(Periph, "[CerfVirtFramebuffer] guest re-moded to %ux%u stride=%u\n",
        width_, height_, Stride());
}
