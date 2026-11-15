#pragma once

#include "surface_overlays.h"

#include <QPointer>
#include <QQuickItem>
#include <QtQml/qqmlregistration.h>

class SurfaceCursorItem : public QQuickItem {
    Q_OBJECT
    QML_ELEMENT
    Q_PROPERTY(SurfaceOverlays* overlays READ Overlays WRITE SetOverlays NOTIFY overlaysChanged)

public:
    explicit SurfaceCursorItem(QQuickItem* parent = nullptr);

    SurfaceOverlays* Overlays() const { return overlays_; }
    void             SetOverlays(SurfaceOverlays* overlays);

signals:
    void overlaysChanged();

protected:
    QSGNode* updatePaintNode(QSGNode* old_node, UpdatePaintNodeData* data) override;

private:
    QPointer<SurfaceOverlays> overlays_;
    QMetaObject::Connection   changed_;
    qint64                    uploaded_key_ = 0;
};
