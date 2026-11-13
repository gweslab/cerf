#include "device_pixel_item.h"

#include "fresh_sampler_texture.h"
#include "qt_device_pixels.h"

#include <QPainter>
#include <QQuickWindow>
#include <QSGImageNode>
#include <QSGTexture>

QSGNode* DevicePixelItem::UpdateNode(QSGNode* old_node) {
    const qreal   dpr   = window()->effectiveDevicePixelRatio();
    const QPointF scale = PixelScale();
    const QSize   size  = DeviceCanvasSize(width(), height(), scale);
    if (image_.size() != size) image_ = QImage(size, QImage::Format_RGBA8888_Premultiplied);
    image_.fill(FillColor());
    QPainter painter(&image_);
    painter.scale(dpr, dpr);
    Paint(&painter);
    painter.end();

    auto* node = static_cast<QSGImageNode*>(old_node);
    if (node == nullptr) {
        node = window()->createImageNode();
        node->setOwnsTexture(true);
        node->setFiltering(QSGTexture::Nearest);
    }
    node->setTexture(CreateFreshSamplerTexture(
        window(), image_, opaque_ ? QQuickWindow::TextureIsOpaque : QQuickWindow::CreateTextureOptions()));
    node->setRect(QRectF(0, 0, size.width() / scale.x(), size.height() / scale.y()));
    return node;
}
