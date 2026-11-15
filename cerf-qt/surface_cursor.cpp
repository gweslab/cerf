#include "surface_cursor.h"

#include "qt_guest_cursor_cache.h"
#include "view_rotation.h"
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

CursorPicture SurfaceCursor::Picture(cerfcore::CerfEmulator& emu, const View& view) {
    if (!Shown(emu, view)) return {};
    int press_x = 0, press_y = 0;
    if (emu.Get<cerfcore::CalibrationPressCursor>().Point(press_x, press_y)) {
        cerffrontend::FramePoint at;
        if (!view.layout.GuestToHost(press_x, press_y, at)) return {};
        return overlay_.Arrow(QPointF(at.x, at.y));
    }
    auto& guest = emu.Get<QtGuestCursorCache>();
    if (view.active_kind == cerfcore::PointerKind::Absolute && guest.Refresh()) {
        if (!guest.Drawable()) return {};
        return overlay_.Guest(guest.Image(), guest.Hotspot(), emu.Get<cerffrontend::ViewRotation>().Quarter(),
                              view.pointer_at, view.guest_scale);
    }
    return overlay_.Arrow(view.pointer_at);
}
