#pragma once

#include <QImage>
#include <QPoint>
#include <QPointF>
#include <QSize>

int    DeviceExtent(qreal logical, qreal dpr);
QSize  DeviceCanvasSize(qreal logical_w, qreal logical_h, qreal dpr);
int    LogicalExtentCovering(int device, qreal dpr);
QPoint DevicePoint(const QPointF& logical, qreal dpr);
QPoint LogicalPoint(int x, int y, qreal dpr);
void   FitDeviceImage(QImage& image, qreal logical_w, qreal logical_h, qreal ratio, QImage::Format format);
