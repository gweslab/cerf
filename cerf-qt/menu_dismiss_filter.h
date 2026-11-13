#pragma once

#include <QObject>
#include <QPointF>

class QMouseEvent;

class MenuDismissFilter final : public QObject {
public:
    void Arm();

protected:
    bool eventFilter(QObject* watched, QEvent* event) override;

private:
    static bool OnPopup(const QPointF& global);
    bool        SwallowMouse(const QMouseEvent& event);

    bool            armed_      = false;
    Qt::MouseButton swallowed_  = Qt::NoButton;
    bool            touch_held_ = false;
};
