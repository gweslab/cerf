#include "pointer_overlay.h"

#include "../qt_device_pixels.h"
#include "../tinted_symbol_icon.h"

#include <QPainter>

namespace {

constexpr qreal kArrowSize = 28.0;
constexpr qreal kArrowHotX = 240.0 / 960.0;
constexpr qreal kArrowHotY = 80.0 / 960.0;

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

void PointerOverlay::PaintGuest(QPainter& painter, const QImage& image, QPoint hotspot, QPointF device_at, qreal dpr,
                                double guest_scale) {
    const QPointF origin = device_at - QPointF(hotspot) * guest_scale;
    painter.drawImage(QRectF(origin / dpr, QSizeF(image.size()) * guest_scale / dpr), image);
}

void PointerOverlay::PaintArrow(QPainter& painter, QPointF device_at, qreal dpr) {
    const QImage& arrow  = Arrow(dpr);
    const QPointF origin = device_at - QPointF(arrow.width() * kArrowHotX, arrow.height() * kArrowHotY);
    painter.drawImage(QRectF(origin / dpr, QSizeF(arrow.size()) / dpr), arrow);
}
