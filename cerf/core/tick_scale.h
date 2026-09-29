#pragma once

#include <cstdint>

inline uint64_t ScaleU64(uint64_t value, uint64_t num, uint64_t den) {
    return (value / den) * num + ((value % den) * num) / den;
}

inline uint64_t ScaleU64Ceil(uint64_t value, uint64_t num, uint64_t den) {
    return (value / den) * num + ((value % den) * num + den - 1u) / den;
}

inline uint64_t MulDivU64(uint64_t a, uint64_t b, uint64_t den) {
    if (b == 0u || a <= UINT64_MAX / b) return a * b / den;
    const uint64_t b_quot = b / den;
    const uint64_t b_rem  = b % den;
    uint64_t q = 0u;
    uint64_t r = 0u;
    for (int bit = 63; bit >= 0; --bit) {
        const bool r_top = (r >> 63) != 0u;
        q <<= 1;
        r <<= 1;
        if (r_top || r >= den) {
            r -= den;
            ++q;
        }
        if ((a >> bit) & 1u) {
            const uint64_t sum = r + b_rem;
            q += b_quot;
            if (sum < r || sum >= den) {
                r = sum - den;
                ++q;
            } else {
                r = sum;
            }
        }
    }
    return q;
}
