#include "host_key_name.h"

#include "host_key_name_table.h"

namespace cerffrontend {

std::string HostKeyName(uint8_t vk) {
    if (const char* name = FindHostKeyName(kHostKeyNames, vk)) return name;
    return UnnamedHostKey(vk);
}

}
