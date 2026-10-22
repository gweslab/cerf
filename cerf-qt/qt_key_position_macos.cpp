#include "qt_key_position.h"

#include "qt_mac_key_vk.h"

#include <QKeyEvent>

#include <iterator>

KeyPositionResult HostKeyPosition(const QKeyEvent* event, QtHostKey& out, uint32_t& native) {
    const uint32_t code = event->nativeVirtualKey();
    native              = code;
    const uint8_t vk    = code < std::size(kMacKeyToVk) ? kMacKeyToVk[code] : uint8_t{0};
    if (vk == 0u) return KeyPositionResult::kNoVirtualKey;
    out.vk       = vk;
    out.sided_vk = MacSidedVk(code, vk);
    out.toggle   = code == kMacKeyCapsLock;
    return KeyPositionResult::kMapped;
}
