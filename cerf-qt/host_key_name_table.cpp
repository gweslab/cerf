#include "host_key_name_table.h"

#include <cstdio>

namespace cerffrontend {

const char* FindHostKeyName(std::span<const HostKeyNameEntry> table, uint8_t vk) {
    for (const HostKeyNameEntry& entry : table)
        if (entry.vk == vk) return entry.name;
    return nullptr;
}

std::string UnnamedHostKey(uint8_t vk) {
    char text[16] = {};
    std::snprintf(text, sizeof(text), "VK 0x%02X", static_cast<unsigned>(vk));
    return text;
}

}
