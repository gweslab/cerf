#pragma once

#include "../core/service.h"

#define NOMINMAX
#include <windows.h>

#include <cstdint>

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
    bool RouteNotificationInput(HWND hwnd, UINT msg, LPARAM lp, LRESULT& out);

    /* Warp the cursor back to centre each move so motion reads as relative
       deltas (RelativeMouseInput); without the warp it drifts to an edge and
       stops generating motion. */
    bool RouteCapturedMouse(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp, LRESULT& out);
    void WarpToCentre(HWND hwnd);
    void ShowLockHintOnce();

    bool pen_down_            = false;
    bool mouse_locked_active_ = false;
    bool lock_hint_shown_     = false;
    uint32_t notification_click_mask_ = 0;
};
