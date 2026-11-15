#pragma once

#include <QImage>
#include <QPoint>
#include <QPointF>
#include <QRectF>

struct CursorPicture {
    QImage  image;
    QRectF  device_rect;
    bool    arrow = false;
    QPointF hot;
};

class PointerOverlay {
public:
    CursorPicture Guest(const QImage& image, QPoint hotspot, int quarter, QPointF device_at, double guest_scale);
    CursorPicture Arrow(QPointF device_at);
};
