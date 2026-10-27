#pragma once

#include "../viewport_layout.h"
#include "../widget_menu_model.h"

#include <cerfcore/core/service.h>

#include <vector>

namespace cerffrontend {

class ViewportMenuTarget {
public:
    virtual ViewportMode Mode() const                  = 0;
    virtual int          IntegerFactor() const         = 0;
    virtual bool         Antialias() const             = 0;
    virtual void         SetViewportMode(ViewportMode m) = 0;
    virtual void         SetIntegerScale(int factor)   = 0;
    virtual void         SetAntialias(bool on)         = 0;
    virtual bool         IsFullscreen() const          = 0;
    virtual void         ToggleFullscreen()            = 0;
    virtual void         SaveScreenshot()              = 0;
    virtual void         CopyScreenshot()              = 0;
    virtual void         AfterModeChange(bool integer_scale) = 0;

protected:
    ~ViewportMenuTarget() = default;
};

class ViewportMenu : public cerfcore::Service {
public:
    using cerfcore::Service::Service;

    void Append(std::vector<MenuItem>& items, ViewportMenuTarget& target);
};

}
