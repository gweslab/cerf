#include "surface_host_pointer.h"

#include "canvas_input.h"
#include "guest_canvas_turn.h"
#include "qt_canvas_mouse_buttons.h"
#include "qt_device_pixels.h"
#include "qt_guest_cursor.h"
#include "viewport_layout.h"

#include <cerfcore/core/cerf_emulator.h>

#include <QCursor>
#include <QQuickItem>
#include <QQuickWindow>
#include <QWheelEvent>

#include <algorithm>
#include <cmath>

namespace {

int WholeScale(double scale) { return std::max(1, static_cast<int>(std::lround(scale))); }

}

SurfaceHostPointer::SurfaceHostPointer(QQuickItem& item, const cerfcore::InstanceGate& gate)
    : item_(item), gate_(gate), lock_(MakeQtPointerLock(*this)) {}

qreal SurfaceHostPointer::Dpr() const { return item_.window()->devicePixelRatio(); }

void SurfaceHostPointer::ApplyCursor(cerfcore::CerfEmulator& emu, int x, int y,
                                     const cerffrontend::ViewportLayout& layout) {
    const cerffrontend::CanvasCursor want = emu.Get<cerffrontend::CanvasInput>().CursorAt(x, y);
    if (hidden_) {
        item_.setCursor(Qt::BlankCursor);
        return;
    }
    switch (want) {
        case cerffrontend::CanvasCursor::kDefault: item_.setCursor(Qt::ArrowCursor); return;
        case cerffrontend::CanvasCursor::kHand:    item_.setCursor(Qt::PointingHandCursor); return;
        case cerffrontend::CanvasCursor::kNone:    item_.setCursor(Qt::BlankCursor); return;
        case cerffrontend::CanvasCursor::kGuest: {
            double sx = 0.0;
            double sy = 0.0;
            layout.GuestPixelScale(sx, sy);
            const QtGuestCursorLook look{
                WholeScale(sx), WholeScale(sy),
                emu.Get<cerffrontend::GuestCanvasTurn>().LogicalQuarter(layout.Presentation().quarter & 3), Dpr()};
            bool          active = false;
            const QCursor cursor = emu.Get<QtGuestCursor>().Resolve(look, active);
            item_.setCursor(active ? cursor : QCursor(Qt::ArrowCursor));
            return;
        }
    }
}

void SurfaceHostPointer::Hover(cerfcore::CerfEmulator& emu, QPointF logical_at,
                               const cerffrontend::ViewportLayout& layout) {
    const QPoint at = DevicePoint(logical_at, Dpr());
    ApplyCursor(emu, at.x(), at.y(), layout);
    cerffrontend::CanvasMouse m;
    m.kind = cerffrontend::CanvasMouse::Kind::kMove;
    m.x    = at.x();
    m.y    = at.y();
    emu.Get<cerffrontend::CanvasInput>().OnMouse(m);
}

void SurfaceHostPointer::Wheel(cerfcore::CerfEmulator& emu, const QWheelEvent& event) {
    const QPoint              at = DevicePoint(event.position(), Dpr());
    cerffrontend::CanvasMouse m;
    m.kind  = cerffrontend::CanvasMouse::Kind::kWheel;
    m.x     = at.x();
    m.y     = at.y();
    m.held  = HeldMouseButtons(event.buttons());
    m.wheel = event.angleDelta().y();
    emu.Get<cerffrontend::CanvasInput>().OnMouse(m);
}

void SurfaceHostPointer::Leave(cerfcore::CerfEmulator& emu) { emu.Get<cerffrontend::CanvasInput>().OnPointerLeave(); }

void SurfaceHostPointer::SetHidden(bool hidden) {
    hidden_ = hidden;
    item_.setCursor(hidden ? Qt::BlankCursor : Qt::ArrowCursor);
}

bool SurfaceHostPointer::WarpTo(int x, int y) {
    if (!lock_->CanWarp()) return false;
    QCursor::setPos(item_.mapToGlobal(QPointF(LogicalPoint(x, y, Dpr()))).toPoint());
    return true;
}

bool SurfaceHostPointer::Lock() {
    rest_x_ = 0;
    rest_y_ = 0;
    return lock_->Lock(*item_.window());
}

QPointF SurfaceHostPointer::RestInWindow() const { return item_.mapToScene(QPointF(item_.width() / 2, item_.height() / 2)); }

void SurfaceHostPointer::Unlock() { lock_->Unlock(); }

void SurfaceHostPointer::OnRelativeMotion(double dx, double dy) {
    const qreal dpr = Dpr();
    rest_x_ += dx * dpr;
    rest_y_ += dy * dpr;
    const int ix = static_cast<int>(rest_x_);
    const int iy = static_cast<int>(rest_y_);
    rest_x_ -= ix;
    rest_y_ -= iy;
    if (ix == 0 && iy == 0) return;
    gate_.Run([ix, iy](cerfcore::CerfEmulator& emu) { emu.Get<cerffrontend::CanvasInput>().OnRelativeMotion(ix, iy); });
}
