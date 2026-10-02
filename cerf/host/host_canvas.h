#pragma once

#include "../core/device_config.h"
#include "../core/service.h"
#include "presenter_canvas.h"

#include <cstdint>
#include <vector>

class HostCanvas : public Service, public PresenterCanvasHost {
public:
    using Service::Service;

    using Tab = CanvasTab;
    using ViewportMode = PresenterCanvas::ViewportMode;

    /* UI thread. Create the child window inside `parent` at `rect`, with the
       guest surface sized to surf_w x surf_h. */
    void CreateOn(HWND parent, const RECT& rect,
                  uint32_t surf_w, uint32_t surf_h);

    /* UI thread. Move/resize the canvas within the parent client. */
    void Reposition(const RECT& rect);

    /* Guest presented-surface native dimensions (atomic, off-thread-safe). */
    uint32_t GuestSurfaceWidth () const { return canvas_.GuestSurfaceWidth();  }
    uint32_t GuestSurfaceHeight() const { return canvas_.GuestSurfaceHeight(); }

    uint32_t ContentWidth () const { return canvas_.ContentWidth();  }
    uint32_t ContentHeight() const { return canvas_.ContentHeight(); }

    /* UI thread. Re-size the guest surface (rebuilds the surface DIB). */
    void SetGuestSurfaceSize(uint32_t w, uint32_t h) {
        canvas_.SetGuestSurfaceSize(w, h);
    }

    /* View state (UI thread). */
    Tab          CurrentTab()    const { return tab_; }
    ViewportMode Mode()          const { return canvas_.Mode(); }
    int          IntegerFactor() const { return canvas_.IntegerFactor(); }
    void SetTab(Tab t, bool user_initiated);
    void SetViewportMode(ViewportMode m) { canvas_.SetViewportMode(m); }
    void SetIntegerScale(int factor)     { canvas_.SetIntegerScale(factor); }

    /* UI thread. Re-arm the one-shot that auto-switches to Framebuffer on the
       first frame, so a guest reboot returns to Framebuffer when video resumes. */
    void RearmFramebufferAutoSwitch();

    bool Antialias() const     { return canvas_.Antialias(); }
    void SetAntialias(bool on) { canvas_.SetAntialias(on); }

    /* UI thread. Render the live guest framebuffer fresh and copy it out 1:1
       for screenshot/clipboard. False if no frame. */
    bool CaptureGuestSurface(std::vector<uint32_t>& out,
                             uint32_t& w, uint32_t& h) {
        return canvas_.CaptureSurface(out, w, h);
    }

    HWND Hwnd() const { return canvas_.Hwnd(); }

    /* canvas-client (cx,cy) -> guest-surface (sx,sy). False when the point is
       outside the blitted guest image. Public for HostCanvasInput. */
    bool HostToGuest(int cx, int cy, int& sx, int& sy) const {
        return canvas_.HostToGuest(cx, cy, sx, sy);
    }
    void ClampGuest(int& sx, int& sy) const { canvas_.ClampGuest(sx, sy); }

    /* PresenterCanvasHost - main-window-only concerns layered on the canvas. */
    void OnPresentTick() override;
    bool RenderAltContent(HDC dc, uint32_t* bits, int w, int h) override;
    bool HandleInput(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp,
                     LRESULT& out) override;
    bool ShouldDesaturatePresent() override;
    void RenderOverlay(HDC dc, int w, int h) override;

private:
    Tab  tab_  = Tab::Boot;   /* set from DeviceConfig.start_tab in CreateOn */
    bool user_picked_view_ = false;
    bool latched_once_     = false;

    PresenterCanvas canvas_{nullptr, this};
};
