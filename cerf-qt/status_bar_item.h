#pragma once

#include <cerfcore/core/instance_gate.h>

#include "device_pixel_item.h"

#include <QColor>
#include <QImage>
#include <QRectF>
#include <QString>
#include <QTimer>
#include <QtQml/qqmlregistration.h>

namespace cerfcore { class HostWidget; }

class StatusBarItem : public DevicePixelItem {
    Q_OBJECT
    QML_ELEMENT
    Q_PROPERTY(QColor background MEMBER background_ NOTIFY colorsChanged)
    Q_PROPERTY(QColor separator MEMBER separator_ NOTIFY colorsChanged)
    Q_PROPERTY(QColor hover MEMBER hover_ NOTIFY colorsChanged)
    Q_PROPERTY(QString tip READ Tip NOTIFY tipChanged)
    Q_PROPERTY(QRectF tipRect READ TipRect NOTIFY tipChanged)

public:
    explicit StatusBarItem(QQuickItem* parent = nullptr);

    void Attach(cerfcore::CerfEmulator& emu);
    void Detach();

    void Paint(QPainter* painter) override;

    QString Tip() const { return tip_; }
    QRectF  TipRect() const { return tip_rect_; }

    bool WidgetSceneRect(const cerfcore::HostWidget* widget, QRectF& out);
    bool CaptureWidgetSceneRect(QRectF& out);

signals:
    void colorsChanged();
    void tipChanged();

protected:
    void geometryChange(const QRectF& new_geometry, const QRectF& old_geometry) override;
    void mousePressEvent(QMouseEvent* event) override;
    void mouseReleaseEvent(QMouseEvent* event) override;
    void hoverMoveEvent(QHoverEvent* event) override;
    void hoverLeaveEvent(QHoverEvent* event) override;
    void wheelEvent(QWheelEvent* event) override;

private:
    void Tick();
    void SecondaryAction(cerfcore::CerfEmulator& emu, cerfcore::HostWidget* widget, QPointF at);
    int  EntryAt(cerfcore::CerfEmulator& emu, QPointF at) const;
    void ShowTip(cerfcore::CerfEmulator& emu, int entry);
    void HideTip();

    cerfcore::InstanceGate gate_;
    QTimer                 tick_;
    QImage                 image_;
    QString                tip_;
    QRectF                 tip_rect_;
    int                    tip_entry_ = -1;
    QColor                 background_;
    QColor                 separator_;
    QColor                 hover_;
};
