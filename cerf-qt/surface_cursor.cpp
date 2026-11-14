#include "surface_cursor.h"

#include "guest_canvas_turn.h"
#include "qt_guest_cursor_cache.h"
#include "viewport_layout.h"

#include <cerfcore/core/cerf_emulator.h>
#include <cerfcore/host/calibration_press_cursor.h>
#include <cerfcore/host/pointer_source.h>

bool SurfaceCursor::Shown(cerfcore::CerfEmulator& emu, const View& view) {
    if (!view.layout.Active()) return false;
    int press_x = 0, press_y = 0;
    if (emu.Get<cerfcore::CalibrationPressCursor>().Point(press_x, press_y)) return true;
    if (!view.cursor_mode || view.relative_pointer) return false;
    auto& guest = emu.Get<QtGuestCursorCache>();
    return view.active_kind != cerfcore::PointerKind::Absolute || !guest.Refresh() || guest.Drawable();
}

void SurfaceCursor::Paint(cerfcore::CerfEmulator& emu, QPainter& painter, const View& view) {
    int press_x = 0, press_y = 0;
    if (emu.Get<cerfcore::CalibrationPressCursor>().Point(press_x, press_y)) {
        cerffrontend::FramePoint at;
        if (view.layout.GuestToHost(press_x, press_y, at)) overlay_.PaintArrow(painter, QPointF(at.x, at.y), view.dpr);
        return;
    }
    auto& guest = emu.Get<QtGuestCursorCache>();
    if (view.active_kind == cerfcore::PointerKind::Absolute && guest.Refresh()) {
        if (guest.Drawable())
            overlay_.PaintGuest(
                painter, guest.Image(), guest.Hotspot(),
                emu.Get<cerffrontend::GuestCanvasTurn>().LogicalQuarter(view.layout.Presentation().quarter),
                view.pointer_at, view.dpr, view.guest_scale);
        return;
    }
    overlay_.PaintArrow(painter, view.pointer_at, view.dpr);
}
