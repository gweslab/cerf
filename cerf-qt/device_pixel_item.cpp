#include "device_pixel_item.h"

#include "qt_device_pixels.h"

#include <QPainter>
#include <QQuickWindow>
#include <QSGImageNode>
#include <QSGTexture>

DevicePixelItem::DevicePixelItem(QQuickItem* parent) : QQuickItem(parent) { setFlag(ItemHasContents, true); }

void DevicePixelItem::SetFillColor(const QColor& color) {
    if (fill_ == color) return;
    fill_ = color;
    emit fillColorChanged();
    update();
}

QSGNode* DevicePixelItem::updatePaintNode(QSGNode* old_node, UpdatePaintNodeData*) {
    if (width() <= 0 || height() <= 0) {
        delete old_node;
        return nullptr;
    }
    const qreal dpr  = window()->effectiveDevicePixelRatio();
    const QSize size = DeviceCanvasSize(width(), height(), dpr);
    if (image_.size() != size) image_ = QImage(size, QImage::Format_RGBA8888_Premultiplied);
    image_.fill(fill_);
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
    node->setTexture(window()->createTextureFromImage(
        image_, opaque_ ? QQuickWindow::TextureIsOpaque : QQuickWindow::CreateTextureOptions()));
    node->setRect(QRectF(0, 0, size.width() / dpr, size.height() / dpr));
    return node;
}
