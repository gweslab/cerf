#define NOMINMAX

#include "window_fullscreen.h"

void WindowFullscreen::Enter(HWND hwnd, bool raise) {
    if (active_ || !hwnd) return;

    saved_place_.length = sizeof(saved_place_);
    GetWindowPlacement(hwnd, &saved_place_);
    saved_style_ = GetWindowLongW(hwnd, GWL_STYLE);
    saved_menu_  = GetMenu(hwnd);

    /* Set active_ before the SWP_FRAMECHANGED below: that resize fires WM_SIZE
       synchronously, and the owner's handler reads IsActive() to lay out. */
    active_ = true;

    SetWindowLongW(hwnd, GWL_STYLE, saved_style_ & ~WS_OVERLAPPEDWINDOW);
    SetMenu(hwnd, nullptr);

    MONITORINFO mi = { sizeof(mi) };
    if (GetMonitorInfoW(MonitorFromWindow(hwnd, MONITOR_DEFAULTTONEAREST), &mi))
        SetWindowPos(hwnd, HWND_TOP,
                     mi.rcMonitor.left, mi.rcMonitor.top,
                     mi.rcMonitor.right  - mi.rcMonitor.left,
                     mi.rcMonitor.bottom - mi.rcMonitor.top,
                     SWP_NOOWNERZORDER | SWP_FRAMECHANGED | SWP_NOACTIVATE |
                     (raise ? 0u : SWP_NOZORDER));
}

void WindowFullscreen::Exit(HWND hwnd) {
    if (!active_ || !hwnd) return;

    active_ = false;

    SetWindowLongW(hwnd, GWL_STYLE, saved_style_);
    SetMenu(hwnd, saved_menu_);
    SetWindowPlacement(hwnd, &saved_place_);
    SetWindowPos(hwnd, nullptr, 0, 0, 0, 0,
                 SWP_NOMOVE | SWP_NOSIZE | SWP_NOZORDER |
                 SWP_NOOWNERZORDER | SWP_FRAMECHANGED | SWP_NOACTIVATE);
}
