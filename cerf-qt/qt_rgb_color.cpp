#include "qt_rgb_color.h"

QColor ToQColor(cerffrontend::Rgb color, int alpha) { return QColor(color.r, color.g, color.b, alpha); }
