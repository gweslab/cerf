#pragma once

#include "painter.h"

#include <QColor>

QColor            ToQColor(cerffrontend::Rgb color, int alpha = 255);
cerffrontend::Rgb FromQColor(const QColor& color);
