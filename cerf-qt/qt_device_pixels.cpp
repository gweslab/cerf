#include "qt_device_pixels.h"

#include <algorithm>
#include <cmath>

int DeviceExtent(qreal logical, qreal dpr) { return static_cast<int>(std::lround(logical * dpr)); }

QSize DeviceCanvasSize(qreal logical_w, qreal logical_h, qreal dpr) {
    return QSize(std::max(DeviceExtent(logical_w, dpr), 1), std::max(DeviceExtent(logical_h, dpr), 1));
}

int LogicalExtentCovering(int device, qreal dpr) { return static_cast<int>(std::ceil(device / dpr)); }

QPoint DevicePoint(const QPointF& logical, qreal dpr) {
    return QPoint(DeviceExtent(logical.x(), dpr), DeviceExtent(logical.y(), dpr));
}

QPoint LogicalPoint(int x, int y, qreal dpr) {
    return QPoint(static_cast<int>(std::lround(x / dpr)), static_cast<int>(std::lround(y / dpr)));
}

void FitDeviceImage(QImage& image, qreal logical_w, qreal logical_h, qreal ratio, QImage::Format format) {
    const QSize size = DeviceCanvasSize(logical_w, logical_h, ratio);
    if (image.size() != size || image.format() != format) image = QImage(size, format);
    image.setDevicePixelRatio(ratio);
}
