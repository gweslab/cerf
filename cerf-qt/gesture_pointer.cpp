#include "gesture_pointer.h"

#include <cerfcore/host/relative_mouse_input.h>

#include <algorithm>

void GesturePointer::Center() {
    cursor_ = host_.VisibleImage().center();
    SendMove();
}

void GesturePointer::Settle() {
    Clamp();
    SendMove();
}

bool GesturePointer::MoveBy(QPointF device_delta) {
    if (RelativePath()) {
        const QPointF guest = device_delta / host_.GuestScale() + relative_rest_;
        const int     dx    = static_cast<int>(guest.x());
        const int     dy    = static_cast<int>(guest.y());
        relative_rest_      = guest - QPointF(dx, dy);
        if (dx != 0 || dy != 0) host_.SendRelative(dx, dy, relative_held_);
        return false;
    }
    cursor_ += device_delta;
    Settle();
    return true;
}

void GesturePointer::Button(GestureButton button, bool down) {
    const uint32_t relative_bit =
        button == GestureButton::kLeft ? cerfcore::kRelMouseLeft : cerfcore::kRelMouseRight;
    if (down ? RelativePath() : (relative_held_ & relative_bit) != 0) {
        relative_held_ = down ? relative_held_ | relative_bit : relative_held_ & ~relative_bit;
        host_.SendRelative(0, 0, relative_held_);
        return;
    }
    const uint32_t bit = button == GestureButton::kLeft ? cerffrontend::kHeldLeft : cerffrontend::kHeldRight;
    held_              = down ? held_ | bit : held_ & ~bit;
    host_.SendCanvasMouse(down ? cerffrontend::CanvasMouse::Kind::kDown : cerffrontend::CanvasMouse::Kind::kUp,
                          button == GestureButton::kLeft ? cerffrontend::MouseButton::kLeft
                                                         : cerffrontend::MouseButton::kRight,
                          cursor_, held_);
}

bool GesturePointer::RelativePath() const {
    return relative_held_ != 0 || (held_ == 0 && host_.RelativeGuestPointer());
}

void GesturePointer::Clamp() {
    const QRectF shown = host_.VisibleImage();
    cursor_.setX(std::clamp(cursor_.x(), shown.left(), std::max(shown.left(), shown.right() - 1.0)));
    cursor_.setY(std::clamp(cursor_.y(), shown.top(), std::max(shown.top(), shown.bottom() - 1.0)));
}

void GesturePointer::SendMove() {
    host_.SendCanvasMouse(cerffrontend::CanvasMouse::Kind::kMove, cerffrontend::MouseButton::kNone, cursor_, held_);
}
