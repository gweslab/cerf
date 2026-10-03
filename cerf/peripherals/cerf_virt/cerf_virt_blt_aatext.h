#pragma once

#include "cerf_virt_blt_pixelops.h"

#include <algorithm>
#include <array>
#include <cstdint>
#include <cmath>

namespace CerfVirt {

struct ClearTypeTables {
    std::array<std::array<uint8_t, 3>, 115> coverage{};

    ClearTypeTables() {
        std::size_t index = 0u;
        for (int r = 0; r <= 6; ++r) {
            const int first_g = r > 2 ? r - 2 : 0;
            const int last_g = r < 4 ? r + 2 : 6;
            for (int g = first_g; g <= last_g; ++g) {
                const int first_b = std::max(0, std::max(g - 2, g - r));
                const int last_b = std::min(6, std::min(g + 2, g + 6 - r));
                for (int b = first_b; b <= last_b; ++b) {
                    coverage[index++] = {static_cast<uint8_t>(r), static_cast<uint8_t>(g), static_cast<uint8_t>(b)};
                }
            }
        }
    }

    static const ClearTypeTables& Get() {
        static const ClearTypeTables tables;
        return tables;
    }
};

struct AATextContext {
    uint32_t fl[3];
    int      shR[3];
    int      shL[3];
    uint32_t uF[3];
    uint32_t aulB[16];
    uint32_t aulIB[16];
    const ClearTypeTables* ct = nullptr;

    void Build(const uint32_t masks[3], uint32_t on_color, float gamma = 2.330f) {
        for (int c = 0; c < 3; ++c) {
            fl[c] = masks[c];
            int r = (int)BltPixelOps::HighBitPos(masks[c]) - 8;
            int l = 0;
            if (r < 0) { l = -r; r = 0; }
            shR[c] = r;
            shL[c] = l;
            uF[c] = ((on_color & masks[c]) >> r) << l;
        }
        for (int k = 0; k < 16; ++k) {
            const float a = (k > 0) ? (float)(k + 1) : 0.0f;
            aulB[k]  = (uint32_t)(65536.0f * std::pow(a / 16.0f, 1.0f / gamma));
            aulIB[k] = (uint32_t)(65536.0f - 65536.0f * std::pow(1.0f - a / 16.0f, 1.0f / gamma));
        }
    }

    void UseClearType() { ct = &ClearTypeTables::Get(); }

    uint32_t BlendAA(uint32_t dst, uint32_t cov) const {
        uint32_t u = 0;
        for (int c = 0; c < 3; ++c) {
            const uint32_t uT = ((dst & fl[c]) << shL[c]) >> shR[c];
            const uint32_t dT = uF[c] - uT;
            const uint32_t* tab = ((int32_t)dT < 0) ? aulIB : aulB;
            u |= ((((dT * tab[cov] + (uT << 16)) >> 16) << shR[c]) >> shL[c]) & fl[c];
        }
        return u;
    }

    uint32_t BlendClearType(uint32_t dst, uint32_t mask_index) const {
        const auto& coverage = ct->coverage[mask_index];
        static constexpr int32_t kBlend[7] = {0x000000, 0x02AAAB, 0x055555, 0x080000, 0x0AAAAB, 0x0D5555, 0x100000};
        uint32_t u = 0;
        for (int c = 0; c < 3; ++c) {
            const uint32_t uT = ((dst & fl[c]) << shL[c]) >> shR[c];
            const int32_t bg = static_cast<int32_t>(uT);
            const int32_t fg = static_cast<int32_t>(uF[c]);
            const uint32_t out = static_cast<uint32_t>(bg + (((fg - bg) * kBlend[coverage[c]] + 0x80000) >> 20));
            u |= (((out << shR[c]) >> shL[c]) & fl[c]);
        }
        return u;
    }
};

}
