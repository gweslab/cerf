#pragma once

#include "touch_gestures.h"

#include <QPointF>
#include <Qt>

class RelativeMouseRelay {
public:
    explicit RelativeMouseRelay(TouchGestureHost& host) : host_(host) {}

    void Move(QPointF at);
    void Button(Qt::MouseButton button, bool down, QPointF at);
    void Forget() { has_last_ = false; }
    void Release();
    bool Held() const { return left_ || right_; }

private:
    void SetButton(GestureButton button, bool& state, bool down);

    TouchGestureHost& host_;
    QPointF           last_;
    bool              has_last_ = false;
    bool              left_     = false;
    bool              right_    = false;
};
