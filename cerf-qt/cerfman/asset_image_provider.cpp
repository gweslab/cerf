#include "asset_image_provider.h"

#include "../qt_resource_paths.h"
#include "../svg_document.h"

AssetImageProvider::AssetImageProvider() : QQuickImageProvider(QQuickImageProvider::Image) {}

QImage AssetImageProvider::requestImage(const QString& id, QSize* size, const QSize& requested_size) {
    const AssetImageRequest request = ParseAssetImageRequest(id);
    const SvgDocument       document(AssetIconResource(request.stem));
    if (request.region.isNull()) return document.RenderRequested(requested_size, size);
    const QSizeF natural = document.DefaultSize();
    const QRect& region  = request.region;
    const qreal  sx      = natural.width() / request.canvas_pixels.width();
    const qreal  sy      = natural.height() / request.canvas_pixels.height();
    *size                = region.size();
    return document.Render(region.size(),
                           QRectF(region.x() * sx, region.y() * sy, region.width() * sx, region.height() * sy));
}
