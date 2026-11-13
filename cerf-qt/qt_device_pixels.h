#pragma once

#include <QImage>
#include <QPoint>
#include <QPointF>
#include <QSize>

int    DeviceExtent(qreal logical, qreal dpr);
QSize  DeviceCanvasSize(qreal logical_w, qreal logical_h, QPointF scale);
int    LogicalExtentCovering(int device, qreal dpr);
QPoint DevicePoint(const QPointF& logical, QPointF scale);
QPoint LogicalPoint(int x, int y, QPointF scale);
void   FitDeviceImage(QImage& image, qreal logical_w, qreal logical_h, qreal ratio, QImage::Format format);
