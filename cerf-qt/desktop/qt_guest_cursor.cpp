#include "qt_guest_cursor.h"

#include "../qt_guest_cursor_cache.h"

#include <cerfcore/core/cerf_emulator.h>

#include <QPixmap>

REGISTER_SERVICE(QtGuestCursor);

QCursor QtGuestCursor::Resolve(bool& active) {
    auto& cache = emu_.Get<QtGuestCursorCache>();
    active      = cache.Refresh();
    if (!active) return QCursor();
    if (cache.Generation() != built_generation_) {
        built_generation_ = cache.Generation();
        built_            = cache.Drawable()
                                ? QCursor(QPixmap::fromImage(cache.Image()), cache.Hotspot().x(), cache.Hotspot().y())
                                : QCursor(Qt::BlankCursor);
    }
    return built_;
}
