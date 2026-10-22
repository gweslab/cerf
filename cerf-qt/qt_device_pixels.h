#pragma once

#include <QPoint>
#include <QPointF>

#include <cmath>

inline int DeviceExtent(qreal logical, qreal dpr) {
    return static_cast<int>(std::lround(logical * dpr));
}

inline int LogicalExtentCovering(int device, qreal dpr) {
    return static_cast<int>(std::ceil(device / dpr));
}

inline QPoint DevicePoint(const QPointF& logical, qreal dpr) {
    return QPoint(DeviceExtent(logical.x(), dpr), DeviceExtent(logical.y(), dpr));
}

inline QPoint LogicalPoint(int x, int y, qreal dpr) {
    return QPoint(static_cast<int>(std::lround(x / dpr)), static_cast<int>(std::lround(y / dpr)));
}
