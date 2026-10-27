#pragma once

#include <QImage>

namespace cerfcore {
struct GuestCursorShape;
}

QImage GuestCursorImage(const cerfcore::GuestCursorShape& shape);
