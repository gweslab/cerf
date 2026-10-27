#include "host_key_name.h"

#include "host_key_name_table.h"

namespace cerffrontend {

namespace {

/* macOS SDK HIToolbox Events.h kVK_Return, kVK_Delete, kVK_ForwardDelete, kVK_Control,
   kVK_Option, kVK_Command and their Right variants, at the VK_* that kMacKeyToVk gives. */
constexpr HostKeyNameEntry kHostKeyNamesMacos[] = {
    {0x08, "Delete"},       {0x0D, "Return"},        {0x11, "Control"},
    {0x12, "Option"},       {0x2E, "Forward Delete"},
    {0x5B, "Left Command"}, {0x5C, "Right Command"},
    {0xA2, "Left Control"}, {0xA3, "Right Control"},
    {0xA4, "Left Option"},  {0xA5, "Right Option"},
};

}

std::string HostKeyName(uint8_t vk) {
    if (const char* name = FindHostKeyName(kHostKeyNamesMacos, vk)) return name;
    if (const char* name = FindHostKeyName(kHostKeyNames, vk)) return name;
    return UnnamedHostKey(vk);
}

}
