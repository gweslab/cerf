#include "qt_guest_cursor.h"

#include "../qt_guest_cursor_cache.h"
#include "../qt_guest_cursor_image.h"

#include <cerfcore/core/cerf_emulator.h>

#include <QGuiApplication>
#include <QPixmap>

REGISTER_SERVICE(QtGuestCursor);

namespace {

enum class HotspotUnits { kLogical, kWaylandSurface, kDevice };

HotspotUnits UnitsOf(const QString& platform) {
    if (platform == QLatin1String("xcb")) return HotspotUnits::kDevice;
    if (platform.startsWith(QLatin1String("wayland"))) return HotspotUnits::kWaylandSurface;
    return HotspotUnits::kLogical;
}

int DeviceHotspot(HotspotUnits units, int logical, qreal dpr) {
    switch (units) {
        case HotspotUnits::kDevice: return logical;
        case HotspotUnits::kWaylandSurface: {
            const int buffer_scale = static_cast<int>(dpr);
            const int surface      = buffer_scale < dpr ? qRound(logical * dpr / buffer_scale) : logical;
            return surface * buffer_scale;
        }
        case HotspotUnits::kLogical: return qRound(logical * dpr);
    }
    return logical;
}

int LogicalHotspot(HotspotUnits units, int device, qreal dpr, int& pad) {
    int logical = 0;
    while (DeviceHotspot(units, logical, dpr) < device) ++logical;
    pad = DeviceHotspot(units, logical, dpr) - device;
    return logical;
}

QCursor BuildCursor(const QtGuestCursorCache& cache, const QtGuestCursorLook& look) {
    if (!cache.Drawable()) return QCursor(Qt::BlankCursor);
    const QImage       picture = TurnedGuestCursor(cache.Image(), look.quarter, look.scale_x, look.scale_y);
    const QPoint       hot     = TurnedGuestHotspot(cache.Hotspot(), cache.Image().size(), look.quarter,
                                                    look.scale_x, look.scale_y);
    const HotspotUnits units   = UnitsOf(QGuiApplication::platformName());
    int                pad_x   = 0;
    int                pad_y   = 0;
    const int          hot_x   = LogicalHotspot(units, hot.x(), look.dpr, pad_x);
    const int          hot_y   = LogicalHotspot(units, hot.y(), look.dpr, pad_y);
    QPixmap pixmap = QPixmap::fromImage(picture.copy(-pad_x, -pad_y, picture.width() + pad_x, picture.height() + pad_y));
    pixmap.setDevicePixelRatio(look.dpr);
    return QCursor(pixmap, hot_x, hot_y);
}

}

QCursor QtGuestCursor::Resolve(const QtGuestCursorLook& look, bool& active) {
    auto& cache = emu_.Get<QtGuestCursorCache>();
    active      = cache.Refresh();
    if (!active) return QCursor();
    if (cache.Generation() != built_generation_ || look != built_look_) {
        built_generation_ = cache.Generation();
        built_look_       = look;
        built_            = BuildCursor(cache, look);
    }
    return built_;
}
