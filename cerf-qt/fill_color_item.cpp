#include "fill_color_item.h"

#include "window_pixel_scale.h"

#include <QMatrix4x4>
#include <QQuickWindow>
#include <QSGNode>
#include <QSGTransformNode>

#include <cmath>

FillColorItem::FillColorItem(QQuickItem* parent) : QQuickItem(parent) { setFlag(ItemHasContents, true); }

void FillColorItem::SetFillColor(const QColor& color) {
    if (fill_ == color) return;
    fill_ = color;
    emit fillColorChanged();
    update();
}

QPointF FillColorItem::PixelScale() const { return pixel_scale_ ? pixel_scale_->Scale() : QPointF(1.0, 1.0); }

void FillColorItem::PixelScaleChanged() { update(); }

void FillColorItem::geometryChange(const QRectF& new_geometry, const QRectF& old_geometry) {
    QQuickItem::geometryChange(new_geometry, old_geometry);
    update();
}

void FillColorItem::itemChange(ItemChange change, const ItemChangeData& value) {
    QQuickItem::itemChange(change, value);
    if (change == ItemSceneChange) WatchWindow(value.window);
    if (change == ItemParentHasChanged || change == ItemSceneChange) WatchAncestors();
    if (change == ItemDevicePixelRatioHasChanged) update();
}

void FillColorItem::WatchWindow(QQuickWindow* window) {
    disconnect(scale_watch_);
    pixel_scale_ = window != nullptr ? WindowPixelScale::Of(window) : nullptr;
    if (pixel_scale_)
        scale_watch_ = connect(pixel_scale_, &WindowPixelScale::scaleChanged, this, &FillColorItem::PixelScaleChanged);
}

void FillColorItem::WatchAncestors() {
    for (const QMetaObject::Connection& connection : ancestor_watch_) disconnect(connection);
    ancestor_watch_.clear();
    for (QQuickItem* ancestor = parentItem(); ancestor != nullptr; ancestor = ancestor->parentItem()) {
        ancestor_watch_.push_back(connect(ancestor, &QQuickItem::xChanged, this, &QQuickItem::update));
        ancestor_watch_.push_back(connect(ancestor, &QQuickItem::yChanged, this, &QQuickItem::update));
        ancestor_watch_.push_back(connect(ancestor, &QQuickItem::parentChanged, this, &FillColorItem::WatchAncestors));
    }
    update();
}

QSGNode* FillColorItem::updatePaintNode(QSGNode* old_node, UpdatePaintNodeData*) {
    if (width() <= 0 || height() <= 0) {
        delete old_node;
        return nullptr;
    }
    auto* snap = static_cast<QSGTransformNode*>(old_node);
    if (snap == nullptr) snap = new QSGTransformNode;
    QSGNode* content = snap->firstChild();
    QSGNode* updated = UpdateNode(content);
    if (content == nullptr) snap->appendChildNode(updated);
    const QPointF scale = PixelScale();
    const QPointF scene = mapToScene(QPointF(0, 0));
    const QPointF origin(scene.x() * scale.x(), scene.y() * scale.y());
    QMatrix4x4    offset;
    offset.translate(static_cast<float>((std::round(origin.x()) - origin.x()) / scale.x()),
                     static_cast<float>((std::round(origin.y()) - origin.y()) / scale.y()));
    snap->setMatrix(offset);
    return snap;
}
