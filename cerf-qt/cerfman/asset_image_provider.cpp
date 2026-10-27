#include "asset_image_provider.h"

#include "../qt_resource_paths.h"
#include "../svg_document.h"

AssetImageProvider::AssetImageProvider() : QQuickImageProvider(QQuickImageProvider::Image) {}

QImage AssetImageProvider::requestImage(const QString& id, QSize* size, const QSize& requested_size) {
    const SvgDocument document(AssetIconResource(id));
    const QSizeF natural = document.DefaultSize();
    const int    w       = requested_size.width();
    const int    h       = requested_size.height();
    QSize        out     = natural.toSize();
    if (w > 0 && h > 0)
        out = QSize(w, h);
    else if (w > 0)
        out = QSize(w, qMax(1, qRound(w * natural.height() / natural.width())));
    else if (h > 0)
        out = QSize(qMax(1, qRound(h * natural.width() / natural.height())), h);
    *size = out;
    return document.Render(out);
}
