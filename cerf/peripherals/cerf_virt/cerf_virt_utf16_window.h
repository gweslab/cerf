#pragma once

#include <cstddef>
#include <cstdint>
#include <string>

namespace CerfVirt {

inline uint32_t Utf16WindowWord(const std::wstring& s, size_t ch) {
    uint32_t v = 0;
    if (ch < s.size())     v |= uint16_t(s[ch]);
    if (ch + 1 < s.size()) v |= uint32_t(uint16_t(s[ch + 1])) << 16;
    return v;
}

}
