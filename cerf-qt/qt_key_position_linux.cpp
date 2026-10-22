#include "qt_key_position.h"

#include "qt_evdev_vk.h"

#include <QKeyEvent>

#include <iterator>

KeyPositionResult HostKeyPosition(const QKeyEvent* event, QtHostKey& out, uint32_t& native) {
    const uint32_t keycode = event->nativeScanCode();
    native                 = keycode;
    if (keycode == 0u) return KeyPositionResult::kNoPosition;
    const uint32_t evdev = keycode - kXKeycodeEvdevOffset;
    const uint8_t  vk    = keycode >= kXKeycodeEvdevOffset && evdev < std::size(kEvdevToVk)
                               ? kEvdevToVk[evdev]
                               : uint8_t{0};
    if (vk == 0u) return KeyPositionResult::kNoVirtualKey;
    out.vk       = vk;
    out.sided_vk = SidedVk(evdev, vk);
    return KeyPositionResult::kMapped;
}
