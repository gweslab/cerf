#include "svg_file_image_provider.h"

#include "../qt_resource_paths.h"
#include "../svg_document.h"

#include <QFile>

SvgFileImageProvider::SvgFileImageProvider() : QQuickImageProvider(QQuickImageProvider::Image) {}

QImage SvgFileImageProvider::requestImage(const QString& id, QSize* size, const QSize& requested_size) {
    QFile file(ParseSvgFileImageRequest(id));
    if (!file.open(QIODevice::ReadOnly)) return QImage();
    const SvgDocument document(file.readAll());
    if (!document.Loaded()) return QImage();
    return document.RenderRequested(requested_size, size);
}
