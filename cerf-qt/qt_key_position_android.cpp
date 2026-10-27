#include "qt_key_position.h"

#include "qt_android_key_vk.h"

#include <QKeyEvent>

KeyPositionResult HostKeyPosition(const QKeyEvent* event, QtHostKey& out, uint32_t& native) {
    const int  combined = event->key();
    const int  key      = combined & ~static_cast<int>(Qt::KeyboardModifierMask);
    const bool keypad   = (combined & Qt::KeypadModifier) != 0 || event->modifiers().testFlag(Qt::KeypadModifier);
    native              = static_cast<uint32_t>(key);
    if (key == 0 || key == Qt::Key_unknown) return KeyPositionResult::kNoPosition;
    for (const AndroidKeyVk& entry : kAndroidKeyVk) {
        if (entry.key != key || entry.keypad != keypad) continue;
        out.vk       = entry.vk;
        out.sided_vk = entry.sided_vk;
        return KeyPositionResult::kMapped;
    }
    return KeyPositionResult::kNoVirtualKey;
}
