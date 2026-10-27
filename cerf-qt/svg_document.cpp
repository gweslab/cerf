#include "svg_document.h"

#include <resvg.h>

#include <QByteArray>
#include <QResource>

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

QImage SvgDocument::Render(const QSize& size) const {
    QImage image(size, QImage::Format_RGBA8888_Premultiplied);
    image.fill(Qt::transparent);
    const resvg_size natural   = resvg_get_image_size(tree_);
    resvg_transform  transform = resvg_transform_identity();
    transform.a                = static_cast<float>(size.width()) / natural.width;
    transform.d                = static_cast<float>(size.height()) / natural.height;
    resvg_render(tree_, transform, static_cast<uint32_t>(size.width()), static_cast<uint32_t>(size.height()),
                 reinterpret_cast<char*>(image.bits()));
    return image;
}
