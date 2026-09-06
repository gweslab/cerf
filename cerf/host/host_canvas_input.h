#pragma once

#include "../core/service.h"

#define NOMINMAX
#include <windows.h>

/* Routes host-window pointer/keyboard/wheel messages to the guest input
   services (TouchInput / PointerInput / KeyboardInput / MemoryVisualizer).
   Split out of HostCanvas, which owns the window, layout, and presentation. */
class HostCanvasInput : public Service {
public:
    using Service::Service;

    /* Returns true (with `out` set) when the message is consumed; `out` is
       the WndProc result HostCanvas returns. */
    bool Handle(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp, LRESULT& out);

    /* HostCanvas calls this when leaving the framebuffer tab so a captured
       touch pen doesn't dangle across the tab switch. */
    void ReleasePenIfDown();

private:
    bool RoutePointerInput(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp);

    /* Warp the cursor back to centre each move so motion reads as relative
       deltas (RelativeMouseInput); without the warp it drifts to an edge and
       stops generating motion. */
    bool RouteCapturedMouse(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp, LRESULT& out);
    void WarpToCentre(HWND hwnd);
    void ShowLockHintOnce();

    bool pen_down_            = false;
    bool mouse_locked_active_ = false;
    bool lock_hint_shown_     = false;
};
