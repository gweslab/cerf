#define NOMINMAX

#include "host_key_binding.h"

#include "../core/cerf_emulator.h"
#include "../core/device_config.h"

#include <cstdio>

REGISTER_SERVICE(HostKeyBinding);

namespace {

constexpr uint8_t  kFallbackHostKeyVk    = VK_RCONTROL;
constexpr uint32_t kExtendedKeyLParamBit = 1u << 24;

/* Microsoft, Keyboard Input Overview, "Extended-Key Flag":
   https://learn.microsoft.com/en-us/windows/win32/inputdev/about-keyboard-input */
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

std::wstring VkLabel(uint8_t vk) {
    const UINT sc = MapVirtualKeyW(vk, MAPVK_VK_TO_VSC);
    if (sc) {
        LONG lparam = (LONG)(sc << 16);
        if (IsExtendedVk(vk)) lparam |= (LONG)kExtendedKeyLParamBit;
        wchar_t name[64] = {};
        if (GetKeyNameTextW(lparam, name, 64) > 0 && name[0] >= L' ')
            return name;
    }
    wchar_t fallback[16] = {};
    swprintf(fallback, 16, L"VK 0x%02X", (unsigned)vk);
    return fallback;
}

}

void HostKeyBinding::OnReady() {
    vks_ = emu_.Get<DeviceConfig>().host_key_vks;
    if (vks_.empty()) vks_.push_back(kFallbackHostKeyVk);

    for (size_t i = 0; i < vks_.size(); i++) {
        if (i) label_ += L'+';
        label_ += VkLabel(vks_[i]);
    }
}

int HostKeyBinding::IndexOf(uint32_t vk) const {
    for (size_t i = 0; i < vks_.size(); i++)
        if (vks_[i] == vk) return (int)i;
    return -1;
}

bool HostKeyBinding::AllMembersDownNow() const {
    for (uint8_t vk : vks_)
        if (!(GetKeyState(vk) & 0x8000)) return false;
    return true;
}

std::wstring HostKeyBinding::LabelWith(const wchar_t* suffix) const {
    return label_ + L'+' + suffix;
}
