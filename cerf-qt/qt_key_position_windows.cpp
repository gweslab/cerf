#define NOMINMAX

#include "qt_key_position.h"

#include <QKeyEvent>

#include <windows.h>

KeyPositionResult HostKeyPosition(const QKeyEvent* event, QtHostKey& out, uint32_t& native) {
    const uint32_t vk = event->nativeVirtualKey();
    native            = vk;
    if (vk == 0u || vk > 0xFFu) return KeyPositionResult::kNoVirtualKey;
    uint32_t sided = vk;
    if (vk == VK_SHIFT || vk == VK_CONTROL || vk == VK_MENU)
        sided = LOWORD(MapVirtualKeyW(event->nativeScanCode(), MAPVK_VSC_TO_VK_EX));
    if (sided == 0u || sided > 0xFFu) return KeyPositionResult::kNoVirtualKey;
    out.vk       = static_cast<uint8_t>(vk);
    out.sided_vk = static_cast<uint8_t>(sided);
    return KeyPositionResult::kMapped;
}
