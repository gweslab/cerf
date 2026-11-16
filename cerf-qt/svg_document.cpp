#include "svg_document.h"

#include <resvg.h>

#include <QByteArray>
#include <QResource>

#include <algorithm>

namespace {

constexpr qreal kContentMarginPart = 1.0 / 64;

}

SvgDocument::SvgDocument(const QString& path) {
    const QByteArray data    = QResource(path).uncompressedData();
    resvg_options*   options = resvg_options_create();
    resvg_parse_tree_from_data(data.constData(), static_cast<uintptr_t>(data.size()), options, &tree_);
    resvg_options_destroy(options);
}

SvgDocument::~SvgDocument() { resvg_tree_destroy(tree_); }

QSizeF SvgDocument::DefaultSize() const {
    const resvg_size size = resvg_get_image_size(tree_);
    return QSizeF(size.width, size.height);
}

QRectF SvgDocument::ContentBounds() const {
    const QSizeF canvas = DefaultSize();
    resvg_rect   bbox{};
    resvg_get_image_bbox(tree_, &bbox);
    const qreal margin = std::max(canvas.width(), canvas.height()) * kContentMarginPart;
    return QRectF(bbox.x, bbox.y, bbox.width, bbox.height).adjusted(-margin, -margin, margin, margin);
}

QImage SvgDocument::Render(const QSize& size) const { return Render(size, QRectF(QPointF(), DefaultSize())); }

QImage SvgDocument::Render(const QSize& size, const QRectF& source) const {
    QImage image(size, QImage::Format_RGBA8888_Premultiplied);
    image.fill(Qt::transparent);
    const qreal     sx        = size.width() / source.width();
    const qreal     sy        = size.height() / source.height();
    resvg_transform transform = resvg_transform_identity();
    transform.a               = static_cast<float>(sx);
    transform.d               = static_cast<float>(sy);
    transform.e               = static_cast<float>(-source.x() * sx);
    transform.f               = static_cast<float>(-source.y() * sy);
    resvg_render(tree_, transform, static_cast<uint32_t>(size.width()), static_cast<uint32_t>(size.height()),
                 reinterpret_cast<char*>(image.bits()));
    return image;
}
