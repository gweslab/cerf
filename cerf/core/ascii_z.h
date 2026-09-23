#pragma once

#include <cstddef>
#include <cstdint>
#include <span>
#include <string>

namespace cerf {

inline std::string ReadAsciiZ(std::span<const uint8_t> bytes, size_t off) {
    std::string s;
    while (off < bytes.size() && bytes[off] != 0) {
        s.push_back(char(bytes[off]));
        ++off;
    }
    return s;
}

}
