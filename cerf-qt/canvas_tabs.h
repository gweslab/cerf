#pragma once

#include <cerfcore/core/device_config.h>
#include <cerfcore/core/service.h>

namespace cerffrontend {

class CanvasTabs : public cerfcore::Service {
public:
    using cerfcore::Service::Service;
    using Tab = cerfcore::CanvasTab;

    void OnReady() override;

    Tab  Current() const { return tab_; }
    bool Set(Tab tab, bool user_initiated);
    void RearmAutoSwitch();
    bool OnPresentTick(bool content_latched);
    bool ShouldDesaturate();

private:
    Tab  tab_              = Tab::Boot;
    bool user_picked_view_ = false;
    bool latched_once_     = false;
};

}
