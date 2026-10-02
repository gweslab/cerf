#pragma once

#define NOMINMAX
#include <windows.h>

#include <atomic>
#include <cstdint>
#include <vector>

#include "canvas_presenter.h"

class FrameSource;

class PresenterCanvasHost {
public:
    virtual ~PresenterCanvasHost() = default;

    /* Run once per present tick, before rendering (e.g. drive the LCD scan
       tick, evaluate the first-frame tab auto-switch). */
    virtual void OnPresentTick() {}

    /* Fill present_bits with owner content (e.g. a non-framebuffer tab) and
       return true; return false to let the canvas compose the FrameSource. */
    virtual bool RenderAltContent(HDC /*present_dc*/, uint32_t* /*present_bits*/,
                                  int /*w*/, int /*h*/) { return false; }

    /* First crack at a window message (pointer/keyboard routing). Return true
       with `out` set to consume it. */
    virtual bool HandleInput(HWND /*hwnd*/, UINT /*msg*/, WPARAM /*wp*/,
                             LPARAM /*lp*/, LRESULT& /*out*/) { return false; }

    virtual bool ShouldDesaturatePresent() { return false; }

    virtual void RenderOverlay(HDC, int, int) {}
};

/* The shared drawable child window: owns the present-DIB backbuffer, a
   CanvasPresenter, and the ~60 Hz present timer. Multi-instance, NOT a Service.
   Keep the window borderless (window rect == client): with a border, toggling a
   scrollbar shrinks the client and latches the bar permanently on. */
class PresenterCanvas {
public:
    using ViewportMode = CanvasPresenter::ViewportMode;

    /* source may be null (HostCanvas binds the board FrameRenderer late via
       SetSource); host may be null (a plain FrameSource-only window). */
    PresenterCanvas(FrameSource* source, PresenterCanvasHost* host)
        : presenter_(source), host_(host) {}
    ~PresenterCanvas();

    PresenterCanvas(const PresenterCanvas&)            = delete;
    PresenterCanvas& operator=(const PresenterCanvas&) = delete;

    void SetSource(FrameSource* source) { presenter_.SetSource(source); }

    /* UI thread. Create the child window inside `parent` at `rect`, guest
       surface sized to surf_w x surf_h. */
    void CreateOn(HWND parent, const RECT& rect,
                  uint32_t surf_w, uint32_t surf_h,
                  UINT present_interval_ms = 16);
    void Reposition(const RECT& rect);

    HWND Hwnd() const { return hwnd_; }

    uint32_t GuestSurfaceWidth () const { return presenter_.SurfaceWidth();  }
    uint32_t GuestSurfaceHeight() const { return presenter_.SurfaceHeight(); }

    uint32_t ContentWidth () const { return (uint32_t)presenter_.ContentWidth();  }
    uint32_t ContentHeight() const { return (uint32_t)presenter_.ContentHeight(); }
    void     SetGuestSurfaceSize(uint32_t w, uint32_t h) {
        presenter_.SetSurfaceSize(w, h);
    }

    ViewportMode Mode()          const { return presenter_.Mode(); }
    bool         Antialias()     const { return presenter_.Antialias(); }
    int          IntegerFactor() const { return presenter_.IntegerFactor(); }
    void SetViewportMode(ViewportMode m) { presenter_.SetViewportMode(m); }
    void SetAntialias(bool on)           { presenter_.SetAntialias(on); }
    void SetIntegerScale(int factor)     { presenter_.SetIntegerScale(factor); }

    /* Whether the FrameSource is the active content (drives scrollbars). The
       main window sets false while a non-framebuffer tab shows. */
    void SetFramebufferActive(bool active) { presenter_.SetActive(active); }
    bool SourceHasFrame() const            { return presenter_.SourceHasFrame(); }

    bool HostToGuest(int cx, int cy, int& sx, int& sy) const {
        return presenter_.HostToGuest(cx, cy, sx, sy);
    }
    void ClampGuest(int& sx, int& sy) const { presenter_.ClampGuest(sx, sy); }
    bool CaptureSurface(std::vector<uint32_t>& out, uint32_t& w, uint32_t& h) {
        return presenter_.CaptureSurface(out, w, h);
    }

private:
    static LRESULT CALLBACK WndProcStatic(HWND, UINT, WPARAM, LPARAM);
    LRESULT WndProc(HWND, UINT, WPARAM, LPARAM);

    void RebuildPresentDib(int w, int h);
    void TickAndPresent();
    static void CALLBACK PresentTimerProc(UINT, UINT, DWORD_PTR, DWORD_PTR,
                                          DWORD_PTR);

    PresenterCanvasHost* host_;

    HWND      hwnd_ = nullptr;

    HDC       present_dc_   = nullptr;
    HBITMAP   present_dib_  = nullptr;
    uint32_t* present_bits_ = nullptr;
    int       canvas_w_ = 0;
    int       canvas_h_ = 0;

    UINT      timer_mm_ = 0;
    std::atomic<bool> present_pending_{ false };
    UINT      present_interval_ms_ = 16;

    CanvasPresenter presenter_;
};
