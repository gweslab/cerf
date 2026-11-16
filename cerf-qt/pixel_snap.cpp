#include "pixel_snap.h"

#include <QMatrix4x4>

PixelSnap::PixelSnap(QObject* parent) : QQuickTransform(parent) {}

void PixelSnap::SetTarget(QQuickItem* target) {
    if (target_ == target) return;
    target_ = target;
    snap_   = std::make_unique<DevicePixelSnap>(target);
    connect(snap_.get(), &DevicePixelSnap::moved, this, &PixelSnap::Realign);
    connect(snap_.get(), &DevicePixelSnap::scaleChanged, this, &PixelSnap::Realign);
    Realign();
    emit targetChanged();
}

void PixelSnap::applyTo(QMatrix4x4* matrix) const {
    matrix->translate(static_cast<float>(offset_.x()), static_cast<float>(offset_.y()));
}

void PixelSnap::Realign() {
    QQuickItem* parent = target_->parentItem();
    if (parent == nullptr) return;
    const QPointF offset = snap_->OffsetAt(parent->mapToScene(target_->position()));
    if (offset == offset_) return;
    offset_ = offset;
    update();
}
