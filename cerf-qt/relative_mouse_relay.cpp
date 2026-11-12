#include "relative_mouse_relay.h"

void RelativeMouseRelay::Move(QPointF at) {
    if (has_last_ && at != last_) host_.PointerMoveBy(at - last_);
    last_     = at;
    has_last_ = true;
}

void RelativeMouseRelay::Button(Qt::MouseButton button, bool down, QPointF at) {
    Move(at);
    if (button == Qt::LeftButton) SetButton(GestureButton::kLeft, left_, down);
    else if (button == Qt::RightButton) SetButton(GestureButton::kRight, right_, down);
}

void RelativeMouseRelay::Release() {
    SetButton(GestureButton::kLeft, left_, false);
    SetButton(GestureButton::kRight, right_, false);
    Forget();
}

void RelativeMouseRelay::SetButton(GestureButton button, bool& state, bool down) {
    if (state == down) return;
    state = down;
    host_.PointerButton(button, down);
}
