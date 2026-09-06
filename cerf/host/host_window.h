#pragma once

#include "../core/service.h"
#include "window_fullscreen.h"

#define NOMINMAX
#include <windows.h>

#include <atomic>
#include <condition_variable>
#include <cstdint>
#include <functional>
#include <mutex>
#include <string>
#include <thread>

class HostWindow : public Service {
public:
    using Service::Service;
    ~HostWindow() override;
    void OnReady() override;
    void OnShutdown() override;

    void OnLcdEnabled();

    /* CerfVirtResize calls this (JIT thread) when the guest acks a re-mode;
       marshals to the UI thread to repoint the framebuffer + canvas surface. */
    void NotifyGuestRemoded(uint32_t guest_w, uint32_t guest_h);

    /* UI thread. Point the host framebuffer + canvas surface at a new guest
       mode. Shared by the guest re-mode ack (kGuestRemodeMsg) and the
       Change-resolution dialog's reset paths (where no guest ack arrives). */
    void SetGuestResolution(uint32_t w, uint32_t h);

    /* UI thread. Fit the window to a new sw x sh guest surface, unless the
       window is maximized - then keep it as-is and let the canvas viewport /
       scrollbars adapt. Used by the Change-resolution dialog. */
    void FitToResolution(uint32_t sw, uint32_t sh);

    /* Any thread. Marshal a switch to the Hardware Screen (text) tab to the UI
       thread (so a guest power-down / save-progress notice is visible).
       rearm_framebuffer re-arms the framebuffer auto-switch so a rebooting
       guest's video returns to it. */
    void ShowHwScreenTab(bool rearm_framebuffer);

    /* Any thread. Switch to the configured startup tab (DeviceConfig.start_tab):
       the boot screen in production, the hardware screen in dev. Used on guest
       reboot / deep-sleep resume. */
    void ShowStartupTab(bool rearm_framebuffer);

    /* Any thread. Run `job` on the main UI thread; dropped if the window is
       gone. Lets an action run off its caller's thread (a VGA card window
       ejecting itself must not run the eject on its own UI thread - the eject
       joins that thread). */
    void RunOnUiThread(std::function<void()> job);

    HWND Hwnd() const { return hwnd_; }

    /* HostMenu's "Match guest size" state + action. */
    bool FollowGuest() const { return follow_guest_; }
    void MatchGuestSize();
    void RefitIfFollowingGuest();

    bool IsFullscreen() const  { return fullscreen_.IsActive(); }
    void ToggleFullscreen()    { if (hwnd_) fullscreen_.Toggle(hwnd_); }

    void BeginShutdownTeardown();

private:
    void StopUiThread();   /* idempotent: close window + join the UI thread */
    void UiThreadMain();
    static LRESULT CALLBACK WndProcStatic(HWND, UINT, WPARAM, LPARAM);
    LRESULT WndProc(HWND, UINT, WPARAM, LPARAM);

    void  AutoResizeToGuest();

    /* Shutdown sequence, all UI-thread, none run inside WM_CLOSE: a posted
       message shows the dialog, the save runs async, and teardown starts from
       the save-completion callback. */
    void  RunShutdownPrompt();

    /* Guest-additions: when adopt-resolution is enabled, size the guest surface
       to the work area of the monitor this window landed on, minus the exact
       window chrome. Runs on the UI thread after the window exists but before
       the canvas is built and before the guest reads its framebuffer dims. */
    void  AdoptResolutionToWindowMonitor();

    /* Non-client + menu + status-bar pixel overhead around a guest surface, at
       the given DPI (Per-Monitor-v2: pass the window's monitor DPI). */
    void  WindowChromeExtent(UINT dpi, int& extra_w, int& extra_h) const;

    /* Size the window so its client holds an sw x sh guest surface, but never
       larger than the work area, and pull the origin in so the whole frame
       stays on-screen. An oversized surface leaves the canvas smaller than the
       surface, which engages the canvas scrollbars. */
    void  FitWindowToSurface(uint32_t sw, uint32_t sh);

    std::thread             ui_thread_;
    std::atomic<bool>       ui_ready_{false};
    std::mutex              ui_ready_mutex_;
    std::condition_variable ui_ready_cv_;

    HWND  hwnd_ = nullptr;

    uint32_t initial_surface_w_ = 0;
    uint32_t initial_surface_h_ = 0;

    bool follow_guest_  = true;   /* false once user resizes/maximizes */
    bool user_resizing_ = false;  /* between WM_ENTER/EXITSIZEMOVE */
    bool user_resized_  = false;

    bool      shutdown_pending_ = false;  /* dialog/save in flight, before teardown */
    bool      closing_          = false;  /* teardown started; waiting on JIT stop */
    ULONGLONG close_start_tick_ = 0;      /* GetTickCount64 at teardown start */

    WindowFullscreen fullscreen_;
};
