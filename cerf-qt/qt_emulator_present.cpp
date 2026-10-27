#include "qt_emulator_present.h"

#include "qt_device_pixels.h"
#include "qt_painter.h"

#include "canvas_input.h"
#include "canvas_tabs.h"
#include "dpi_scale.h"
#include "notification_overlay.h"

#include <cerfcore/core/cerf_emulator.h>

#include <QPainter>

int QtEmulatorPresent::Dpi() const { return DeviceExtent(cerffrontend::kDefaultDpi, dpr_()); }

void QtEmulatorPresent::OnPresentTick(bool source_has_frame) {
    const bool activate = emu_.Get<cerffrontend::CanvasTabs>().OnPresentTick(source_has_frame);
    emu_.Get<cerffrontend::CanvasInput>().RefreshLock();
    if (activate) framebuffer_ready_();
}

bool QtEmulatorPresent::RenderAlt(uint32_t* bits, int w, int h) {
    return emu_.Get<cerffrontend::CanvasTabs>().RenderAlt(bits, w, h, Dpi());
}

bool QtEmulatorPresent::ShouldDesaturate() { return emu_.Get<cerffrontend::CanvasTabs>().ShouldDesaturate(); }

void QtEmulatorPresent::RenderOverlay(QImage& present, int w, int h) {
    QPainter  p(&present);
    QtPainter painter(emu_, p);
    emu_.Get<cerffrontend::NotificationOverlay>().Render(painter, w, h, Dpi());
}
