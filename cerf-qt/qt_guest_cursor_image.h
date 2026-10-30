#pragma once

#include <QImage>
#include <QPoint>
#include <QSize>

namespace cerfcore {
struct GuestCursorShape;
}

QImage GuestCursorImage(const cerfcore::GuestCursorShape& shape);
QImage TurnedGuestCursor(const QImage& image, int quarter, int scale_x, int scale_y);
QPoint TurnedGuestHotspot(QPoint hotspot, QSize size, int quarter, int scale_x, int scale_y);
