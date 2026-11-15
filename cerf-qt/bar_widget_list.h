#pragma once

#include "bar_widget.h"
#include "overlay_item_model.h"

#include <cerfcore/core/instance_gate.h>

#include <QAbstractItemModel>
#include <QObject>
#include <QPointF>
#include <QRectF>
#include <QTimer>
#include <QVariantMap>
#include <QtQml/qqmlregistration.h>

#include <cstdint>
#include <vector>

class BarWidgetList : public QObject {
    Q_OBJECT
    QML_ELEMENT
    Q_PROPERTY(QAbstractItemModel* items READ Items CONSTANT)
    Q_PROPERTY(bool strip MEMBER strip_ NOTIFY stripChanged)

public:
    explicit BarWidgetList(QObject* parent = nullptr);

    void Attach(cerfcore::CerfEmulator& emu);
    void Detach();

    QAbstractItemModel* Items() { return &items_; }

    Q_INVOKABLE void Activate(int row, QPointF scene_point, bool menu);
    Q_INVOKABLE void PlaceWidget(int row, QRectF scene_rect);

    bool WidgetSceneRect(uint64_t widget_id, QRectF& out) const;
    bool CaptureWidgetSceneRect(QRectF& out) const;

signals:
    void stripChanged();

private:
    struct ShownWidget {
        uint64_t id      = 0;
        bool     capture = false;
        QRectF   box;
    };

    void        Tick();
    bool        Shown(cerfcore::CerfEmulator& emu, const cerffrontend::BarWidget* widget) const;
    QVariantMap Row(const cerffrontend::BarWidget* widget) const;
    void        RunWidget(cerfcore::CerfEmulator& emu, cerffrontend::BarWidget* widget, QPointF scene_point, bool menu);

    cerfcore::InstanceGate   gate_;
    QTimer                   tick_;
    OverlayItemModel         items_;
    std::vector<ShownWidget> shown_;
    bool                     strip_ = false;
};
