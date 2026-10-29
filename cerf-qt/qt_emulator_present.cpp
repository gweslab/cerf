#include "qt_emulator_present.h"

#include "qt_device_pixels.h"
#include "qt_emulator_view.h"
#include "qt_painter.h"

#include "canvas_input.h"
#include "canvas_tabs.h"
#include "dpi_scale.h"
#include "notification_overlay.h"

#include <cerfcore/core/cerf_emulator.h>

#include <QPainter>

int QtEmulatorPresent::Dpi(qreal dpr) { return DeviceExtent(cerffrontend::kDefaultDpi, dpr); }

void QtEmulatorPresent::OnPresentTick(cerfcore::CerfEmulator& emu, bool source_has_frame) {
    const bool activate = emu.Get<cerffrontend::CanvasTabs>().OnPresentTick(source_has_frame);
    emu.Get<cerffrontend::CanvasInput>().RefreshLock();
    if (activate) view_.SetFramebufferActive(true);
}

bool QtEmulatorPresent::RenderAlt(cerfcore::CerfEmulator& emu, uint32_t* bits, int w, int h, qreal dpr) {
    return emu.Get<cerffrontend::CanvasTabs>().RenderAlt(bits, w, h, Dpi(dpr));
}

bool QtEmulatorPresent::ShouldDesaturate(cerfcore::CerfEmulator& emu) {
    return emu.Get<cerffrontend::CanvasTabs>().ShouldDesaturate();
}

void QtEmulatorPresent::RenderOverlay(cerfcore::CerfEmulator& emu, QImage& present, int w, int h, qreal dpr) {
    QPainter  p(&present);
    QtPainter painter(emu, p);
    emu.Get<cerffrontend::NotificationOverlay>().Render(painter, w, h, Dpi(dpr));
}
