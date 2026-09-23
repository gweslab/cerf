#define _CRT_SECURE_NO_WARNINGS
#include "mac_address.h"

#include <cstdio>

namespace cerf::inet {

MacText FormatMac(const uint8_t* mac) {
    MacText t{};
    std::snprintf(t.s, sizeof(t.s), "%02X:%02X:%02X:%02X:%02X:%02X",
                  mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
    return t;
}

bool ParseMac(const std::string& text, MacAddress& out) {
    unsigned bytes[kEthMacSize] = {};
    const int n = std::sscanf(text.c_str(), "%02X:%02X:%02X:%02X:%02X:%02X",
                              &bytes[0], &bytes[1], &bytes[2],
                              &bytes[3], &bytes[4], &bytes[5]);
    if (n != int(kEthMacSize)) return false;
    for (size_t i = 0; i < kEthMacSize; i++) out[i] = uint8_t(bytes[i]);
    return true;
}

}
