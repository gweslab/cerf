#pragma once

#include "../core/service.h"

#define NOMINMAX
#include <windows.h>

#include <atomic>
#include <cstdint>
#include <vector>

/* Child window for the host-window drawable area. Runs entirely on
   HostWindow's UI thread; the ONLY members touched off-thread are the
   atomic guest-surface dims — a touch sampler thread reads them, so a
   non-atomic dim member would be a data race. */

class HostCanvas : public Service {
public:
    using Service::Service;
    ~HostCanvas() override;

    void OnReady() override;

    enum class Tab         { Uart, Framebuffer, MemoryVisualizer };
    enum class ViewportMode { Original, Aspect, Stretch };

    /* UI thread. Create the child window inside `parent` at `rect`, with the
       guest surface sized to surf_w x surf_h. */
    void CreateOn(HWND parent, const RECT& rect,
                  uint32_t surf_w, uint32_t surf_h);

    /* UI thread. Move/resize the canvas within the parent client. */
    void Reposition(const RECT& rect);

    /* Guest presented-surface native dimensions — what the FrameRenderer
       draws at, and the coordinate span touch maps against. Atomic so the
       touch sampler threads can read them. */
    uint32_t GuestSurfaceWidth () const { return surface_w_.load(std::memory_order_acquire); }
    uint32_t GuestSurfaceHeight() const { return surface_h_.load(std::memory_order_acquire); }

    /* UI thread. Re-size the guest surface (rebuilds the surface DIB). */
    void SetGuestSurfaceSize(uint32_t w, uint32_t h);

    /* View state (UI thread). */
    Tab          CurrentTab() const { return tab_; }
    ViewportMode Mode()       const { return mode_; }
    void SetTab(Tab t, bool user_initiated);
    void SetViewportMode(ViewportMode m);

    bool Antialias() const { return antialias_; }
    void SetAntialias(bool on);

    /* UI thread. Render the live guest framebuffer fresh into the surface
       and copy it out 1:1 for screenshot/clipboard. False if no frame. */
    bool CaptureGuestSurface(std::vector<uint32_t>& out,
                             uint32_t& w, uint32_t& h);

    HWND Hwnd() const { return hwnd_; }

private:
    static LRESULT CALLBACK WndProcStatic(HWND, UINT, WPARAM, LPARAM);
    LRESULT WndProc(HWND, UINT, WPARAM, LPARAM);

    void TickAndPresent();
    void ComposeFramebuffer();
    void RebuildPresentDib(int w, int h);
    void RebuildGuestDib(uint32_t w, uint32_t h);
    void UpdateScrollbars();

    /* Both ComposeFramebuffer and HostToGuest derive from this one Layout —
       computing the touch transform with separate math would land taps off
       the rendered image whenever the two drift. */
    struct Layout {
        int  dst_x, dst_y, dst_w, dst_h;
        int  src_x, src_y, src_w, src_h;
        bool stretch;
    };
    Layout ComputeLayout() const;

    /* canvas-client (cx,cy) -> guest-surface (sx,sy). Returns false when the
       point is outside the blitted guest image. */
    bool HostToGuest(int cx, int cy, int& sx, int& sy) const;
    void ClampGuest(int& sx, int& sy) const;
    void ReleasePenIfDown();

    HWND      hwnd_   = nullptr;
    HWND      parent_ = nullptr;

    HDC       present_dc_   = nullptr;   /* wraps present_dib_  (canvas-sized) */
    HBITMAP   present_dib_  = nullptr;
    uint32_t* present_bits_ = nullptr;
    HDC       guest_dc_     = nullptr;   /* wraps guest_dib_ (surface-sized) */
    HBITMAP   guest_dib_    = nullptr;
    uint32_t* guest_bits_   = nullptr;

    int       canvas_w_ = 0;
    int       canvas_h_ = 0;
    std::atomic<uint32_t> surface_w_{0};
    std::atomic<uint32_t> surface_h_{0};

    UINT_PTR  timer_id_ = 0;

    Tab          tab_  = Tab::Uart;
    ViewportMode mode_ = ViewportMode::Original;
    bool         antialias_ = false;  /* off = crisp nearest-neighbor scale */
    bool         user_picked_view_ = false;
    bool         latched_once_     = false;

    int  scroll_x_ = 0;
    int  scroll_y_ = 0;
    bool hsb_shown_ = false;
    bool vsb_shown_ = false;

    bool pen_down_ = false;
};
