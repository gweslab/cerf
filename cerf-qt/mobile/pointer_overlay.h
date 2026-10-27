#pragma once

#include <QImage>
#include <QPoint>
#include <QPointF>

class QPainter;

inline constexpr char kCursorIconName[] = "arrow_selector_tool";

class PointerOverlay {
public:
    void PaintGuest(QPainter& painter, const QImage& image, QPoint hotspot, QPointF device_at, qreal dpr,
                    double guest_scale);
    void PaintArrow(QPainter& painter, QPointF device_at, qreal dpr);

private:
    const QImage& Arrow(qreal dpr);

    QImage arrow_;
    qreal  arrow_dpr_ = 0.0;
};
