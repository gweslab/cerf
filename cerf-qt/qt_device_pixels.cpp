#include "qt_device_pixels.h"

#include <algorithm>
#include <cmath>

int DeviceExtent(qreal logical, qreal dpr) { return static_cast<int>(std::lround(logical * dpr)); }

QSize DeviceCanvasSize(qreal logical_w, qreal logical_h, QPointF scale) {
    return QSize(std::max(DeviceExtent(logical_w, scale.x()), 1), std::max(DeviceExtent(logical_h, scale.y()), 1));
}

int LogicalExtentCovering(int device, qreal dpr) { return static_cast<int>(std::ceil(device / dpr)); }

QPoint DevicePoint(const QPointF& logical, QPointF scale) {
    return QPoint(DeviceExtent(logical.x(), scale.x()), DeviceExtent(logical.y(), scale.y()));
}

QPoint LogicalPoint(int x, int y, QPointF scale) {
    return QPoint(static_cast<int>(std::lround(x / scale.x())), static_cast<int>(std::lround(y / scale.y())));
}

void FitDeviceImage(QImage& image, qreal logical_w, qreal logical_h, qreal ratio, QImage::Format format) {
    const QSize size = DeviceCanvasSize(logical_w, logical_h, QPointF(ratio, ratio));
    if (image.size() != size || image.format() != format) image = QImage(size, format);
    image.setDevicePixelRatio(ratio);
}
