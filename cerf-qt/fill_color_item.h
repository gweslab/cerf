#pragma once

#include "device_pixel_snap.h"

#include <QColor>
#include <QPointF>
#include <QQuickItem>
#include <QtQml/qqmlregistration.h>

class FillColorItem : public QQuickItem {
    Q_OBJECT
    QML_ANONYMOUS
    Q_PROPERTY(QColor fillColor READ FillColor WRITE SetFillColor NOTIFY fillColorChanged)

public:
    explicit FillColorItem(QQuickItem* parent = nullptr);

    QColor  FillColor() const { return fill_; }
    void    SetFillColor(const QColor& color);
    QPointF PixelScale() const;

signals:
    void fillColorChanged();

protected:
    virtual QSGNode* UpdateNode(QSGNode* old_node) = 0;
    virtual void     PixelScaleChanged();

    void     geometryChange(const QRectF& new_geometry, const QRectF& old_geometry) override;
    void     itemChange(ItemChange change, const ItemChangeData& value) override;
    QSGNode* updatePaintNode(QSGNode* old_node, UpdatePaintNodeData* data) final;

private:
    QColor          fill_ = Qt::transparent;
    DevicePixelSnap snap_;
};
