#include "device_pixel_snap.h"

#include "window_pixel_scale.h"

#include <QQuickItem>
#include <QQuickWindow>

#include <cmath>

DevicePixelSnap::DevicePixelSnap(QQuickItem* item) : item_(item) {
    connect(item_, &QQuickItem::windowChanged, this, [this](QQuickWindow* window) {
        WatchWindow(window);
        WatchAncestors();
    });
    connect(item_, &QQuickItem::parentChanged, this, &DevicePixelSnap::WatchAncestors);
    connect(item_, &QQuickItem::xChanged, this, &DevicePixelSnap::moved);
    connect(item_, &QQuickItem::yChanged, this, &DevicePixelSnap::moved);
    WatchWindow(item_->window());
    WatchAncestors();
}

QPointF DevicePixelSnap::Scale() const { return pixel_scale_ ? pixel_scale_->Scale() : QPointF(1.0, 1.0); }

QPointF DevicePixelSnap::OffsetAt(const QPointF& scene_origin) const {
    const QPointF scale = Scale();
    const QPointF device(scene_origin.x() * scale.x(), scene_origin.y() * scale.y());
    return QPointF((std::round(device.x()) - device.x()) / scale.x(), (std::round(device.y()) - device.y()) / scale.y());
}

void DevicePixelSnap::WatchWindow(QQuickWindow* window) {
    disconnect(scale_watch_);
    pixel_scale_ = window != nullptr ? WindowPixelScale::Of(window) : nullptr;
    if (pixel_scale_)
        scale_watch_ = connect(pixel_scale_, &WindowPixelScale::scaleChanged, this, &DevicePixelSnap::scaleChanged);
}

void DevicePixelSnap::WatchAncestors() {
    for (const QMetaObject::Connection& connection : ancestor_watch_) disconnect(connection);
    ancestor_watch_.clear();
    for (QQuickItem* ancestor = item_->parentItem(); ancestor != nullptr; ancestor = ancestor->parentItem()) {
        ancestor_watch_.push_back(connect(ancestor, &QQuickItem::xChanged, this, &DevicePixelSnap::moved));
        ancestor_watch_.push_back(connect(ancestor, &QQuickItem::yChanged, this, &DevicePixelSnap::moved));
        ancestor_watch_.push_back(connect(ancestor, &QQuickItem::parentChanged, this, &DevicePixelSnap::WatchAncestors));
    }
    emit moved();
}
