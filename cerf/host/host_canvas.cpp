#define NOMINMAX

#include "host_canvas.h"

#include "../core/cerf_emulator.h"
#include "../core/log.h"
#include "emulation_pause.h"
#include "frame_renderer.h"
#include "guest_deep_sleep.h"
#include "host_canvas_input.h"
#include "host_focus_policy.h"
#include "boot_screen.h"
#include "hw_screen.h"
#include "notification_overlay.h"
#include "refresh_rate_service.h"

REGISTER_SERVICE(HostCanvas);

void HostCanvas::CreateOn(HWND parent, const RECT& rect,
                          uint32_t surf_w, uint32_t surf_h) {
    tab_ = emu_.Get<DeviceConfig>().start_tab;
    canvas_.SetSource(emu_.TryGet<FrameRenderer>());
    const int rate = emu_.Get<RefreshRateService>().GetRefreshRate();
    const UINT interval = rate > 0 ? (UINT)(1000 / rate) : 16;
    canvas_.CreateOn(parent, rect, surf_w, surf_h, interval < 1 ? 1 : interval);
    emu_.Get<HostFocusPolicy>().Focus(canvas_.Hwnd());
    canvas_.SetFramebufferActive(tab_ == Tab::Framebuffer);
}

void HostCanvas::Reposition(const RECT& r) {
    canvas_.Reposition(r);
}

void HostCanvas::SetTab(Tab t, bool user_initiated) {
    if (user_initiated) user_picked_view_ = true;
    if (tab_ == t) return;
    if (tab_ == Tab::Framebuffer) emu_.Get<HostCanvasInput>().ReleasePenIfDown();
    tab_ = t;
    canvas_.SetFramebufferActive(tab_ == Tab::Framebuffer);
    if (canvas_.Hwnd()) InvalidateRect(canvas_.Hwnd(), nullptr, FALSE);
}

void HostCanvas::RearmFramebufferAutoSwitch() {
    /* A guest reboot returns to the Framebuffer when video resumes, so the
       user's prior manual tab pick is stale - clear it too, else once the user
       ever switches tabs the reboot auto-switch is suppressed forever. */
    latched_once_     = false;
    user_picked_view_ = false;
}

void HostCanvas::OnPresentTick() {
    const bool has_frame = canvas_.SourceHasFrame();
    if (has_frame && !latched_once_) {
        latched_once_ = true;
        emu_.Get<BootScreen>().OnFramebufferLatched();
        if (!user_picked_view_) {
            tab_ = Tab::Framebuffer;
            canvas_.SetFramebufferActive(true);
        }
    }
}

bool HostCanvas::RenderAltContent(HDC dc, uint32_t* bits, int w, int h) {
    if (tab_ == Tab::Framebuffer) return false;   /* canvas composes the frame */
    if (tab_ == Tab::Boot) {
        emu_.Get<BootScreen>().RenderInto(dc, bits, (uint32_t)w, (uint32_t)h);
        return true;
    }
    emu_.Get<HwScreen>().RenderInto(dc, bits, (uint32_t)w, (uint32_t)h);
    return true;
}

bool HostCanvas::ShouldDesaturatePresent() {
    return tab_ == Tab::Framebuffer &&
           (emu_.Get<EmulationPause>().IsPaused() || emu_.Get<GuestDeepSleep>().Asleep());
}

void HostCanvas::RenderOverlay(HDC dc, int w, int h) {
    emu_.Get<NotificationOverlay>().RenderInto(canvas_.Hwnd(), dc, w, h);
}

bool HostCanvas::HandleInput(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp,
                             LRESULT& out) {
    return emu_.Get<HostCanvasInput>().Handle(hwnd, msg, wp, lp, out);
}
