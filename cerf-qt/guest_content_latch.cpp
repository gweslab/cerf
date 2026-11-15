#include "guest_content_latch.h"

#include <cerfcore/core/cerf_emulator.h>
#include <cerfcore/core/log.h>
#include <cerfcore/host/frame_renderer.h>
#include <cerfcore/host/guest_power_notifier.h>

namespace cerffrontend {

REGISTER_SERVICE(GuestContentLatch);

namespace {

constexpr size_t   kSampleStride = 251;
constexpr uint32_t kColorBits    = 0x00FFFFFFu;
constexpr uint64_t kFnvBasis     = 14695981039346656037ull;
constexpr uint64_t kFnvPrime     = 1099511628211ull;

}

void GuestContentLatch::OnReady() {
    renderer_  = &emu_.Get<cerfcore::FrameRenderer>();
    auto& power = emu_.Get<cerfcore::GuestPowerNotifier>();
    power.RegisterRebootListener([this] { rearm_.store(true, std::memory_order_release); });
    power.RegisterResetReleasedListener([this] { CaptureBaseline(); });
}

std::optional<GuestContentLatch::Sample> GuestContentLatch::RenderSampleLocked() {
    if (!renderer_->HasFrame()) return std::nullopt;
    uint32_t w = 0, h = 0;
    renderer_->PresentedSize(w, h);
    if (w == 0 || h == 0) return std::nullopt;
    pixels_.resize(static_cast<size_t>(w) * h);
    renderer_->RenderInto(pixels_.data(), w, h);
    Sample sample;
    sample.sig = kFnvBasis;
    for (size_t i = 0; i < pixels_.size(); i += kSampleStride) {
        const uint32_t color = pixels_[i] & kColorBits;
        sample.lit |= color != 0u;
        sample.sig = (sample.sig ^ color) * kFnvPrime;
    }
    return sample;
}

void GuestContentLatch::ApplyRearmLocked() {
    if (!rearm_.exchange(false, std::memory_order_acq_rel)) return;
    awaiting_release_ = true;
    latched_          = false;
}

void GuestContentLatch::CaptureBaseline() {
    std::lock_guard<std::mutex> lk(mtx_);
    ApplyRearmLocked();
    if (!awaiting_release_) return;
    awaiting_release_ = false;
    const std::optional<Sample> sample = RenderSampleLocked();
    rearmed_ = sample.has_value();
    if (sample) baseline_ = sample->sig;
}

bool GuestContentLatch::Probe() {
    std::lock_guard<std::mutex> lk(mtx_);
    ApplyRearmLocked();
    if (latched_) return true;
    if (awaiting_release_) return false;
    const std::optional<Sample> sample = RenderSampleLocked();
    if (!sample) return false;
    if (rearmed_) {
        if (!sample->lit) {
            baseline_ = sample->sig;
            return false;
        }
        if (sample->sig == baseline_) return false;
        rearmed_ = false;
    }
    if (!sample->lit) return false;
    latched_ = true;
    LOG(Lcd, "guest content latched (sig=0x%016llX)\n", static_cast<unsigned long long>(sample->sig));
    return true;
}

}
