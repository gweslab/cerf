#pragma once

#include "../core/service.h"

#define NOMINMAX
#include <windows.h>

#include <atomic>
#include <condition_variable>
#include <cstdint>
#include <mutex>
#include <thread>

class HostWindow : public Service {
public:
    using Service::Service;
    ~HostWindow() override;
    void OnReady() override;

    /* SoC LCD service calls on guest panel-enable edge. fb_(w|h) are raw
       LCD-controller dimensions; run through the FrameRenderer's HostSizeFor
       so rotating renderers can swap. */
    void OnLcdEnabled(uint32_t fb_w, uint32_t fb_h);

    HWND Hwnd() const { return hwnd_; }

private:
    void UiThreadMain();
    static LRESULT CALLBACK WndProcStatic(HWND, UINT, WPARAM, LPARAM);
    LRESULT WndProc(HWND, UINT, WPARAM, LPARAM);

    HMENU BuildMenu();
    void  SyncMenu();
    void  HandleCommand(int id);
    void  AutoResizeToGuest();

    /* Size the window so its client holds an sw x sh guest surface, but never
       larger than the work area, and pull the origin in so the whole frame
       stays on-screen. An oversized surface leaves the canvas smaller than the
       surface, which engages the canvas scrollbars. */
    void  FitWindowToSurface(uint32_t sw, uint32_t sh);

    std::thread             ui_thread_;
    std::atomic<bool>       ui_ready_{false};
    std::mutex              ui_ready_mutex_;
    std::condition_variable ui_ready_cv_;

    HWND  hwnd_  = nullptr;
    HMENU hmenu_ = nullptr;

    uint32_t initial_surface_w_ = 0;
    uint32_t initial_surface_h_ = 0;

    bool follow_guest_  = true;   /* false once user resizes/maximizes */
    bool user_resizing_ = false;  /* between WM_ENTER/EXITSIZEMOVE */
};
