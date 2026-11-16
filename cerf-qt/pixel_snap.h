#pragma once

#include "device_pixel_snap.h"

#include <QPointF>
#include <QQuickItem>
#include <QtQml/qqmlregistration.h>

#include <memory>

class PixelSnap : public QQuickTransform {
    Q_OBJECT
    QML_ELEMENT
    Q_PROPERTY(QQuickItem* target READ Target WRITE SetTarget NOTIFY targetChanged)

public:
    explicit PixelSnap(QObject* parent = nullptr);

    QQuickItem* Target() const { return target_; }
    void        SetTarget(QQuickItem* target);
    void        applyTo(QMatrix4x4* matrix) const override;

signals:
    void targetChanged();

private:
    void Realign();

    QQuickItem*                      target_ = nullptr;
    std::unique_ptr<DevicePixelSnap> snap_;
    QPointF                          offset_;
};
