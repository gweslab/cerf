#include "qt_emulator_present.h"

#include "qt_device_pixels.h"
#include "qt_emulator_view.h"
#include "qt_painter.h"

#include "canvas_input.h"
#include "canvas_tabs.h"
#include "dpi_scale.h"
#include "hud_renderer.h"
#include "hud_selection.h"
#include "notification_overlay.h"
#include "screenshots.h"
#include "shader_selection.h"

#include <cerfcore/core/cerf_emulator.h>

#include <QPainter>

int QtEmulatorPresent::Dpi(qreal dpr) { return DeviceExtent(cerffrontend::kDefaultDpi, dpr); }

void QtEmulatorPresent::OnPresentTick(cerfcore::CerfEmulator&, bool source_has_frame) {
    source_has_frame_.store(source_has_frame, std::memory_order_release);
}

void QtEmulatorPresent::OnUiTick(cerfcore::CerfEmulator& emu) {
    if (emu.Get<cerffrontend::CanvasTabs>().OnPresentTick(source_has_frame_.load(std::memory_order_acquire)))
        view_.SetFramebufferActive(true);
    emu.Get<cerffrontend::CanvasInput>().RefreshLock();
}

bool QtEmulatorPresent::RenderAlt(cerfcore::CerfEmulator& emu, uint32_t* bits, int w, int h, qreal dpr) {
    return emu.Get<cerffrontend::CanvasTabs>().RenderAlt(bits, w, h, Dpi(dpr));
}

bool QtEmulatorPresent::ShouldDesaturate(cerfcore::CerfEmulator& emu) {
    return emu.Get<cerffrontend::CanvasTabs>().ShouldDesaturate();
}

double QtEmulatorPresent::GlowReach(cerfcore::CerfEmulator& emu, const cerffrontend::ViewportLayout::Layout& frame) {
    return emu.Get<cerffrontend::HudSelection>().PanelReach(frame);
}

const ShaderChainSpec* QtEmulatorPresent::Shaders(cerfcore::CerfEmulator& emu) {
    return &emu.Get<cerffrontend::ShaderSelection>().Spec();
}

void QtEmulatorPresent::ShadersApplied(cerfcore::CerfEmulator& emu, const ShaderChainResult& result) {
    emu.Get<cerffrontend::ShaderSelection>().Report(result);
}

void QtEmulatorPresent::ShadedCaptured(cerfcore::CerfEmulator& emu, const ShadedFrame* frame) {
    emu.Get<cerffrontend::Screenshots>().ShadedCaptured(frame);
}

bool QtEmulatorPresent::OverlayShown(cerfcore::CerfEmulator& emu) {
    return emu.Get<cerffrontend::HudSelection>().Shown() || emu.Get<cerffrontend::NotificationOverlay>().Showing() ||
           view_.CursorShown(emu);
}

void QtEmulatorPresent::RenderFrameOverlay(cerfcore::CerfEmulator& emu, QImage& present,
                                           const cerffrontend::ViewportLayout::Layout& frame, qreal dpr) {
    QPainter  p(&present);
    QtPainter painter(emu, p);
    emu.Get<cerffrontend::HudRenderer>().Render(painter, frame, Dpi(dpr));
}

void QtEmulatorPresent::RenderOverlay(cerfcore::CerfEmulator& emu, QImage& present, int w, int h, qreal dpr) {
    {
        QPainter  p(&present);
        QtPainter painter(emu, p);
        emu.Get<cerffrontend::NotificationOverlay>().Render(painter, w, h, Dpi(dpr));
    }
    if (!view_.CursorShown(emu)) return;
    QPainter cursor(&present);
    cursor.scale(dpr, dpr);
    view_.PaintCursor(emu, cursor);
}
