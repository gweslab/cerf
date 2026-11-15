#include "surface_cursor_item.h"

#include "fresh_sampler_texture.h"

#include <QQuickWindow>
#include <QSGImageNode>

SurfaceCursorItem::SurfaceCursorItem(QQuickItem* parent) : QQuickItem(parent) {
    setFlag(ItemHasContents, true);
}

void SurfaceCursorItem::SetOverlays(SurfaceOverlays* overlays) {
    if (overlays_ == overlays) return;
    QObject::disconnect(changed_);
    overlays_ = overlays;
    if (overlays != nullptr) changed_ = QObject::connect(overlays, &SurfaceOverlays::cursorChanged, this, &QQuickItem::update);
    emit overlaysChanged();
    update();
}

QSGNode* SurfaceCursorItem::updatePaintNode(QSGNode* old_node, UpdatePaintNodeData*) {
    auto* node = static_cast<QSGImageNode*>(old_node);
    if (overlays_ == nullptr || overlays_->Cursor().image.isNull()) {
        delete node;
        uploaded_key_ = 0;
        return nullptr;
    }
    const CursorPicture& cursor = overlays_->Cursor();
    if (node == nullptr) {
        node = window()->createImageNode();
        node->setOwnsTexture(true);
        node->setFiltering(QSGTexture::Nearest);
        uploaded_key_ = 0;
    }
    if (cursor.image.cacheKey() != uploaded_key_) {
        node->setTexture(CreateFreshSamplerTexture(window(), cursor.image, {}));
        uploaded_key_ = cursor.image.cacheKey();
    }
    const QPointF scale = overlays_->Scale();
    node->setRect(QRectF(cursor.device_rect.x() / scale.x(), cursor.device_rect.y() / scale.y(),
                         cursor.device_rect.width() / scale.x(), cursor.device_rect.height() / scale.y()));
    return node;
}
