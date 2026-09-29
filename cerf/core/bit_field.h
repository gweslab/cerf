#pragma once

#include <cstdint>

namespace cerf {

constexpr uint32_t BitField(uint32_t value, uint32_t shift, uint32_t mask) {
    return (value >> shift) & mask;
}

}
