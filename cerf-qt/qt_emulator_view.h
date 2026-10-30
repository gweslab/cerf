#pragma once

#include "view_presentation.h"

#include <cstdint>
#include <vector>

class QtEmulatorView {
public:
    virtual void     SetPresentation(const cerffrontend::ViewPresentation& presentation) = 0;
    virtual void     SetFramebufferActive(bool active)                                    = 0;
    virtual void     Repaint()                                                            = 0;
    virtual void     SetGuestSurfaceSize(uint32_t w, uint32_t h)                          = 0;
    virtual uint32_t GuestSurfaceWidth() const                                            = 0;
    virtual uint32_t GuestSurfaceHeight() const                                           = 0;
    virtual bool     CaptureSurface(std::vector<uint32_t>& out, uint32_t& w, uint32_t& h) = 0;

protected:
    ~QtEmulatorView() = default;
};
