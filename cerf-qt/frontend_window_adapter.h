#pragma once

#include "frontend_window.h"

namespace cerffrontend {

class FrontendWindowAdapter : public FrontendWindow {
public:
    using FrontendWindow::FrontendWindow;

    Tab      CurrentTab() const override;
    void     SetTab(Tab tab, bool user_initiated) override;
    bool     IsFullscreen() const override;
    void     ToggleFullscreen() override;
    void     MatchGuestSize() override;
    void     RefitIfFollowingGuest() override;
    void     OnPresentationChanged() override;
    void     SetGuestResolution(uint32_t w, uint32_t h) override;
    void     FitToResolution(uint32_t w, uint32_t h) override;
    void     OnLcdEnabled() override;
    void     NotifyGuestRemoded(uint32_t w, uint32_t h) override;
    uint32_t GuestSurfaceWidth() const override;
    uint32_t GuestSurfaceHeight() const override;
    void     SetGuestSurfaceSize(uint32_t w, uint32_t h) override;
    void     RunOnUiThread(std::function<void()> job) override;
    void     RunOnUiThreadAfter(uint32_t delay_ms, std::function<void()> job) override;
    bool     CaptureGuestSurface(std::vector<uint32_t>& out, uint32_t& w, uint32_t& h) override;
    uint64_t NativeHandle() const override;

protected:
    virtual FrontendWindow& PlatformWindow() const = 0;
};

}
