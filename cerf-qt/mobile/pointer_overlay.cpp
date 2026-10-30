#include "pointer_overlay.h"

#include "../qt_device_pixels.h"
#include "../qt_guest_cursor_image.h"
#include "../tinted_symbol_icon.h"

#include <QPainter>

namespace {

constexpr qreal kArrowSize = 28.0;

}

const QImage& PointerOverlay::Arrow(qreal dpr) {
    if (!arrow_.isNull() && arrow_dpr_ == dpr) return arrow_;
    const int     side    = DeviceExtent(kArrowSize, dpr);
    const QString stem    = QString::fromLatin1(kCursorIconName);
    const QImage  outline = TintedSymbolIcon(stem, QSize(side, side), Qt::black);
    arrow_                = QImage(side, side, QImage::Format_ARGB32_Premultiplied);
    arrow_.fill(Qt::transparent);
    QPainter p(&arrow_);
    const int reach = DeviceExtent(1.5, dpr);
    for (int dx = -reach; dx <= reach; dx += reach)
        for (int dy = -reach; dy <= reach; dy += reach) p.drawImage(QPoint(dx, dy), outline);
    p.drawImage(QPoint(0, 0), TintedSymbolIcon(stem, QSize(side, side), Qt::white));
    p.end();
    arrow_dpr_ = dpr;
    return arrow_;
}

void PointerOverlay::PaintGuest(QPainter& painter, const QImage& image, QPoint hotspot, int quarter, QPointF device_at,
                                qreal dpr, double guest_scale) {
    const QImage  turned = TurnedGuestCursor(image, quarter, 1, 1);
    const QPointF origin = device_at - QPointF(TurnedGuestHotspot(hotspot, image.size(), quarter, 1, 1)) * guest_scale;
    painter.drawImage(QRectF(origin / dpr, QSizeF(turned.size()) * guest_scale / dpr), turned);
}

void PointerOverlay::PaintArrow(QPainter& painter, QPointF device_at, qreal dpr) {
    const QImage& arrow  = Arrow(dpr);
    const QPointF origin = device_at - QPointF(arrow.width() * kCursorIconHotX, arrow.height() * kCursorIconHotY);
    painter.drawImage(QRectF(origin / dpr, QSizeF(arrow.size()) / dpr), arrow);
}
