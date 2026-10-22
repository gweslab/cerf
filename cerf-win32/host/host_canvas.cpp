#define NOMINMAX

#include "host_canvas.h"

#include <cerfcore/core/cerf_emulator.h>
#include <cerfcore/core/log.h>
#include <cerfcore/host/frame_renderer.h>
#include "host_canvas_input.h"
#include "host_dpi.h"
#include "host_focus_policy.h"
#include "win32_painter.h"
#include <cerfcore/host/refresh_rate_service.h>
#include <cerffrontend/canvas_tabs.h>
#include <cerffrontend/dpi_scale.h>
#include <cerffrontend/notification_overlay.h>

#include <algorithm>

REGISTER_SERVICE(HostCanvas);

void HostCanvas::CreateOn(HWND parent, const RECT& rect,
                          uint32_t surf_w, uint32_t surf_h) {
    canvas_.SetSource(emu_.TryGet<cerfcore::FrameRenderer>());
    const UINT interval =
        static_cast<UINT>(emu_.Get<cerfcore::RefreshRateService>().FrameIntervalMs());
    canvas_.CreateOn(parent, rect, surf_w, surf_h, interval);
    emu_.Get<HostFocusPolicy>().Focus(canvas_.Hwnd());
    canvas_.SetFramebufferActive(CurrentTab() == Tab::Framebuffer);
}

void HostCanvas::Reposition(const RECT& r) {
    canvas_.Reposition(r);
}

HostCanvas::Tab HostCanvas::CurrentTab() const {
    return emu_.Get<cerffrontend::CanvasTabs>().Current();
}

void HostCanvas::SetTab(Tab t, bool user_initiated) {
    if (!emu_.Get<cerffrontend::CanvasTabs>().Set(t, user_initiated)) return;
    canvas_.SetFramebufferActive(t == Tab::Framebuffer);
    if (canvas_.Hwnd()) InvalidateRect(canvas_.Hwnd(), nullptr, FALSE);
}

void HostCanvas::OnPresentTick() {
    if (emu_.Get<cerffrontend::CanvasTabs>().OnPresentTick(canvas_.SourceHasFrame()))
        canvas_.SetFramebufferActive(true);
}

bool HostCanvas::RenderAltContent(HDC, uint32_t* bits, int w, int h) {
    return emu_.Get<cerffrontend::CanvasTabs>().RenderAlt(bits, w, h, cerffrontend::kDefaultDpi);
}

bool HostCanvas::ShouldDesaturatePresent() {
    return emu_.Get<cerffrontend::CanvasTabs>().ShouldDesaturate();
}

void HostCanvas::RenderOverlay(HDC dc, int w, int h) {
    RECT client{};
    GetClientRect(canvas_.Hwnd(), &client);
    Win32Painter painter(emu_, dc);
    emu_.Get<cerffrontend::NotificationOverlay>().Render(
        painter, std::min(w, (int)client.right), std::min(h, (int)client.bottom),
        (int)emu_.Get<HostDpi>().ForWindow(canvas_.Hwnd()));
}

bool HostCanvas::HandleInput(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp,
                             LRESULT& out) {
    return emu_.Get<HostCanvasInput>().Handle(hwnd, msg, wp, lp, out);
}
