#include "qt_canvas_mouse_buttons.h"

uint32_t HeldMouseButtons(Qt::MouseButtons buttons) {
    uint32_t held = 0;
    if (buttons & Qt::LeftButton) held |= cerffrontend::kHeldLeft;
    if (buttons & Qt::RightButton) held |= cerffrontend::kHeldRight;
    if (buttons & Qt::MiddleButton) held |= cerffrontend::kHeldMiddle;
    return held;
}

cerffrontend::MouseButton CanvasMouseButton(Qt::MouseButton button) {
    switch (button) {
        case Qt::LeftButton:   return cerffrontend::MouseButton::kLeft;
        case Qt::RightButton:  return cerffrontend::MouseButton::kRight;
        case Qt::MiddleButton: return cerffrontend::MouseButton::kMiddle;
        default:               return cerffrontend::MouseButton::kNone;
    }
}
