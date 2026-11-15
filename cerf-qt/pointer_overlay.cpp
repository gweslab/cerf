#include "pointer_overlay.h"

#include "qt_guest_cursor_image.h"

CursorPicture PointerOverlay::Guest(const QImage& image, QPoint hotspot, int quarter, QPointF device_at,
                                    double guest_scale) {
    const QImage  turned = TurnedGuestCursor(image, quarter, 1, 1);
    const QPointF origin = device_at - QPointF(TurnedGuestHotspot(hotspot, image.size(), quarter, 1, 1)) * guest_scale;
    return {turned, QRectF(origin, QSizeF(turned.size()) * guest_scale), false, QPointF()};
}

CursorPicture PointerOverlay::Arrow(QPointF device_at) { return {QImage(), QRectF(), true, device_at}; }
