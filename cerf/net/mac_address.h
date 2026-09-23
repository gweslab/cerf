#pragma once

#include "ipv4_packet.h"

#include <array>
#include <cstdint>
#include <string>

namespace cerf::inet {

using MacAddress = std::array<uint8_t, kEthMacSize>;

struct MacText {
    char s[3 * kEthMacSize];
};

MacText FormatMac(const uint8_t* mac);

bool ParseMac(const std::string& text, MacAddress& out);

}
