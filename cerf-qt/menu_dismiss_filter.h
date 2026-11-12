#pragma once

#include <QObject>

class QMouseEvent;

class MenuDismissFilter final : public QObject {
public:
    void Arm();

protected:
    bool eventFilter(QObject* watched, QEvent* event) override;

private:
    bool SwallowMouse(const QMouseEvent& event);

    bool            armed_      = false;
    Qt::MouseButton swallowed_  = Qt::NoButton;
    bool            touch_held_ = false;
};
