#pragma once

#include <QColor>
#include <QMetaObject>
#include <QPointF>
#include <QPointer>
#include <QQuickItem>
#include <QtQml/qqmlregistration.h>

#include <vector>

class WindowPixelScale;

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
    void WatchWindow(QQuickWindow* window);
    void WatchAncestors();

    QColor                               fill_ = Qt::transparent;
    QPointer<WindowPixelScale>           pixel_scale_;
    QMetaObject::Connection              scale_watch_;
    std::vector<QMetaObject::Connection> ancestor_watch_;
};
