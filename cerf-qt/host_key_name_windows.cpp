#define NOMINMAX

#include "host_key_name.h"

#include "host_key_name_table.h"

#include <cerfcore/platform/wide_text_win32.h>

#include <windows.h>

namespace cerffrontend {

namespace {

constexpr uint32_t kExtendedKeyLParamBit = 1u << 24;

bool IsExtendedVk(uint8_t vk) {
    switch (vk) {
        case VK_RMENU:
        case VK_RCONTROL:
        case VK_INSERT:
        case VK_DELETE:
        case VK_HOME:
        case VK_END:
        case VK_PRIOR:
        case VK_NEXT:
        case VK_LEFT:
        case VK_RIGHT:
        case VK_UP:
        case VK_DOWN:
        case VK_CANCEL:
        case VK_SNAPSHOT:
        case VK_DIVIDE:
        case VK_LWIN:
        case VK_RWIN:
        case VK_APPS:
            return true;
        default:
            return false;
    }
}

}

std::string HostKeyName(uint8_t vk) {
    const UINT sc = MapVirtualKeyW(vk, MAPVK_VK_TO_VSC);
    if (sc) {
        LONG lparam = static_cast<LONG>(sc << 16);
        if (IsExtendedVk(vk)) lparam |= static_cast<LONG>(kExtendedKeyLParamBit);
        wchar_t name[64] = {};
        if (GetKeyNameTextW(lparam, name, 64) > 0 && name[0] >= L' ')
            return cerfcore::WideToUtf8(name);
    }
    return UnnamedHostKey(vk);
}

}
