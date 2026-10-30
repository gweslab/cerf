#include "frontend_window_adapter.h"

#include <utility>

namespace cerffrontend {

FrontendWindow::Tab FrontendWindowAdapter::CurrentTab() const { return PlatformWindow().CurrentTab(); }

void FrontendWindowAdapter::SetTab(Tab tab, bool user_initiated) { PlatformWindow().SetTab(tab, user_initiated); }

bool FrontendWindowAdapter::IsFullscreen() const { return PlatformWindow().IsFullscreen(); }

void FrontendWindowAdapter::ToggleFullscreen() { PlatformWindow().ToggleFullscreen(); }

void FrontendWindowAdapter::MatchGuestSize() { PlatformWindow().MatchGuestSize(); }

void FrontendWindowAdapter::RefitIfFollowingGuest() { PlatformWindow().RefitIfFollowingGuest(); }

void FrontendWindowAdapter::OnPresentationChanged() { PlatformWindow().OnPresentationChanged(); }

void FrontendWindowAdapter::SetGuestResolution(uint32_t w, uint32_t h) { PlatformWindow().SetGuestResolution(w, h); }

void FrontendWindowAdapter::FitToResolution(uint32_t w, uint32_t h) { PlatformWindow().FitToResolution(w, h); }

void FrontendWindowAdapter::OnLcdEnabled() { PlatformWindow().OnLcdEnabled(); }

void FrontendWindowAdapter::NotifyGuestRemoded(uint32_t w, uint32_t h) { PlatformWindow().NotifyGuestRemoded(w, h); }

uint32_t FrontendWindowAdapter::GuestSurfaceWidth() const { return PlatformWindow().GuestSurfaceWidth(); }

uint32_t FrontendWindowAdapter::GuestSurfaceHeight() const { return PlatformWindow().GuestSurfaceHeight(); }

void FrontendWindowAdapter::SetGuestSurfaceSize(uint32_t w, uint32_t h) { PlatformWindow().SetGuestSurfaceSize(w, h); }

void FrontendWindowAdapter::RunOnUiThread(std::function<void()> job) { PlatformWindow().RunOnUiThread(std::move(job)); }

void FrontendWindowAdapter::RunOnUiThreadAfter(uint32_t delay_ms, std::function<void()> job) {
    PlatformWindow().RunOnUiThreadAfter(delay_ms, std::move(job));
}

bool FrontendWindowAdapter::CaptureGuestSurface(std::vector<uint32_t>& out, uint32_t& w, uint32_t& h) {
    return PlatformWindow().CaptureGuestSurface(out, w, h);
}

uint64_t FrontendWindowAdapter::NativeHandle() const { return PlatformWindow().NativeHandle(); }

}
