#pragma once

#include <QMetaObject>
#include <QObject>
#include <QPointF>
#include <QPointer>
#include <QQuickItem>

#include <vector>

class QQuickWindow;
class WindowPixelScale;

class DevicePixelSnap : public QObject {
    Q_OBJECT

public:
    explicit DevicePixelSnap(QQuickItem* item);

    QPointF Scale() const;
    QPointF OffsetAt(const QPointF& scene_origin) const;

signals:
    void scaleChanged();
    void moved();

private:
    void WatchWindow(QQuickWindow* window);
    void WatchAncestors();

    QQuickItem*                          item_;
    QPointer<WindowPixelScale>           pixel_scale_;
    QMetaObject::Connection              scale_watch_;
    std::vector<QMetaObject::Connection> ancestor_watch_;
};
