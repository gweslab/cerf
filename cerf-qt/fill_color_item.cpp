#include "fill_color_item.h"

#include <QMatrix4x4>
#include <QSGNode>
#include <QSGTransformNode>

FillColorItem::FillColorItem(QQuickItem* parent) : QQuickItem(parent), snap_(this) {
    setFlag(ItemHasContents, true);
    connect(&snap_, &DevicePixelSnap::scaleChanged, this, &FillColorItem::PixelScaleChanged);
    connect(&snap_, &DevicePixelSnap::moved, this, &QQuickItem::update);
}

void FillColorItem::SetFillColor(const QColor& color) {
    if (fill_ == color) return;
    fill_ = color;
    emit fillColorChanged();
    update();
}

QPointF FillColorItem::PixelScale() const { return snap_.Scale(); }

void FillColorItem::PixelScaleChanged() { update(); }

void FillColorItem::geometryChange(const QRectF& new_geometry, const QRectF& old_geometry) {
    QQuickItem::geometryChange(new_geometry, old_geometry);
    update();
}

void FillColorItem::itemChange(ItemChange change, const ItemChangeData& value) {
    QQuickItem::itemChange(change, value);
    if (change == ItemDevicePixelRatioHasChanged) update();
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
    const QPointF shift = snap_.OffsetAt(mapToScene(QPointF(0, 0)));
    QMatrix4x4    offset;
    offset.translate(static_cast<float>(shift.x()), static_cast<float>(shift.y()));
    snap->setMatrix(offset);
    return snap;
}
