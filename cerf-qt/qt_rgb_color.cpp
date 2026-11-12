#include "qt_rgb_color.h"

QColor ToQColor(cerffrontend::Rgb color, int alpha) { return QColor(color.r, color.g, color.b, alpha); }

cerffrontend::Rgb FromQColor(const QColor& color) {
    return cerffrontend::Rgb{static_cast<uint8_t>(color.red()), static_cast<uint8_t>(color.green()),
                             static_cast<uint8_t>(color.blue())};
}
