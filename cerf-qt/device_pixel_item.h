#pragma once

#include <QColor>
#include <QImage>
#include <QQuickItem>
#include <QtQml/qqmlregistration.h>

class QPainter;

class DevicePixelItem : public QQuickItem {
    Q_OBJECT
    QML_ANONYMOUS
    Q_PROPERTY(QColor fillColor READ FillColor WRITE SetFillColor NOTIFY fillColorChanged)

public:
    explicit DevicePixelItem(QQuickItem* parent = nullptr);

    virtual void Paint(QPainter* painter) = 0;

    QColor FillColor() const { return fill_; }
    void   SetFillColor(const QColor& color);
    void   SetOpaquePainting(bool opaque) { opaque_ = opaque; }

signals:
    void fillColorChanged();

protected:
    QSGNode* updatePaintNode(QSGNode* old_node, UpdatePaintNodeData* data) override;

private:
    QImage image_;
    QColor fill_   = Qt::transparent;
    bool   opaque_ = false;
};
