#pragma once

#include <cerfcore/core/device_config.h>
#include <cerfcore/core/service.h>

#include <cstdint>
#include <functional>
#include <vector>

namespace cerffrontend {

class FrontendWindow : public cerfcore::Service {
public:
    using cerfcore::Service::Service;
    using Tab = cerfcore::CanvasTab;

    virtual Tab  CurrentTab() const                     = 0;
    virtual void SetTab(Tab tab, bool user_initiated)   = 0;

    virtual bool IsFullscreen() const    = 0;
    virtual void ToggleFullscreen()      = 0;
    virtual void MatchGuestSize()        = 0;
    virtual void RefitIfFollowingGuest() = 0;

    virtual void SetGuestResolution(uint32_t w, uint32_t h) = 0;
    virtual void FitToResolution(uint32_t w, uint32_t h)    = 0;

    virtual void     OnLcdEnabled()                                    = 0;
    virtual void     NotifyGuestRemoded(uint32_t w, uint32_t h)        = 0;
    virtual uint32_t GuestSurfaceWidth() const                         = 0;
    virtual uint32_t GuestSurfaceHeight() const                        = 0;
    virtual void     SetGuestSurfaceSize(uint32_t w, uint32_t h)       = 0;

    virtual void RunOnUiThread(std::function<void()> job) = 0;
    virtual void RunOnUiThreadAfter(uint32_t delay_ms, std::function<void()> job) = 0;
    virtual bool CaptureGuestSurface(std::vector<uint32_t>& out, uint32_t& w, uint32_t& h) = 0;
    virtual uint64_t NativeHandle() const = 0;
};

}
