#include "ce_imgfs_xpress.h"

#include <cstring>

namespace cerf::ce_imgfs_xpress {

namespace {

inline uint16_t Rd16(const uint8_t* p) {
    return uint16_t(p[0]) | (uint16_t(p[1]) << 8);
}
inline uint32_t Rd32(const uint8_t* p) {
    return uint32_t(p[0])
         | (uint32_t(p[1]) << 8)
         | (uint32_t(p[2]) << 16)
         | (uint32_t(p[3]) << 24);
}

}

std::vector<uint8_t> Decompress(const uint8_t* src,
                                size_t          src_size,
                                size_t          out_size) {
    std::vector<uint8_t> dst(out_size, 0);
    size_t si = 0;
    size_t di = 0;
    size_t nibble_idx = 0;  /* 0 means "no pending high-nibble" */

    while (si < src_size && di < out_size) {
        if (si + 4 > src_size) break;
        const uint32_t flags = Rd32(src + si);
        si += 4;

        for (int bit = 31; bit >= 0; --bit) {
            if (si >= src_size || di >= out_size) break;

            if ((flags & (1u << bit)) == 0) {
                /* Literal. */
                dst[di++] = src[si++];
                continue;
            }
            /* Match. */
            if (si + 2 > src_size) return std::vector<uint8_t>(dst.begin(), dst.begin() + di);
            const uint16_t val = Rd16(src + si);
            si += 2;
            const uint32_t match_off = (val >> 3) + 1;
            uint32_t       match_len = val & 7;

            if (match_len == 7) {
                /* Nibble-shared first extension byte. */
                if (nibble_idx == 0) {
                    if (si >= src_size) return std::vector<uint8_t>(dst.begin(), dst.begin() + di);
                    nibble_idx = si;
                    match_len  = src[si] & 0x0F;
                    ++si;
                } else {
                    match_len  = src[nibble_idx] >> 4;
                    nibble_idx = 0;
                }
                if (match_len == 15) {
                    /* 8-bit extension. */
                    if (si >= src_size) return std::vector<uint8_t>(dst.begin(), dst.begin() + di);
                    match_len = src[si++];
                    if (match_len == 255) {
                        /* 16-bit extension. */
                        if (si + 2 > src_size) return std::vector<uint8_t>(dst.begin(), dst.begin() + di);
                        match_len = Rd16(src + si);
                        si += 2;
                        if (match_len == 0) {
                            /* 32-bit extension. */
                            if (si + 4 > src_size) return std::vector<uint8_t>(dst.begin(), dst.begin() + di);
                            match_len = Rd32(src + si);
                            si += 4;
                        }
                        if (match_len < 22) return std::vector<uint8_t>(dst.begin(), dst.begin() + di);
                        match_len -= 22;
                    }
                    match_len += 15;
                }
                match_len += 7;
            }
            match_len += 3;

            if (match_off > di) {
                return std::vector<uint8_t>(dst.begin(), dst.begin() + di);
            }
            const size_t copy_from = di - match_off;
            for (uint32_t k = 0; k < match_len && di < out_size; ++k) {
                dst[di] = dst[copy_from + k];
                ++di;
            }
        }
    }
    return std::vector<uint8_t>(dst.begin(), dst.begin() + di);
}

}
