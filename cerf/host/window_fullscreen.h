#pragma once

#define NOMINMAX
#include <windows.h>

/* Borderless true-fullscreen toggle for one top-level window: save placement +
   style, strip the frame and menu, cover the current monitor; restore on exit.
   Plain per-window helper owned by each window on its own UI thread. */
class WindowFullscreen {
public:
    bool IsActive() const { return active_; }

    /* The owning window's UI thread. */
    void Toggle(HWND hwnd, bool raise) { active_ ? Exit(hwnd) : Enter(hwnd, raise); }
    void Enter(HWND hwnd, bool raise);
    void Exit(HWND hwnd);

private:
    bool            active_      = false;
    WINDOWPLACEMENT saved_place_ = { sizeof(WINDOWPLACEMENT) };
    LONG            saved_style_ = 0;
    HMENU           saved_menu_  = nullptr;
};
