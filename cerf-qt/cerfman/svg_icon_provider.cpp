#include "svg_icon_provider.h"

#include "../qt_resource_paths.h"
#include "../tinted_symbol_icon.h"

SvgIconProvider::SvgIconProvider() : QQuickImageProvider(QQuickImageProvider::Image) {}

QImage SvgIconProvider::requestImage(const QString& id, QSize* size, const QSize& requested_size) {
    const TintedIconRequest request = ParseTintedIconRequest(id);
    QImage                  image   = TintedSymbolIcon(request.stem, requested_size, request.color);
    *size                           = image.size();
    return image;
}
