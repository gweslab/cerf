#pragma once

#include <cstdint>

struct Omap3530DpllFreqSelBand {
    uint32_t sel;
    uint64_t lo_hz;
    uint64_t hi_hz;
};

/* SPRUF98Y Table 4-112 (printed p. 437) MPU_DPLL_FREQSEL and Table 4-178
   (printed p. 467) PERIPH_DPLL_FREQSEL: DPLL internal frequency ranges. */
inline constexpr Omap3530DpllFreqSelBand kOmap3530DpllFreqSelBands[] = {
    { 0x3u,   750000u,  1000000u }, { 0x4u,  1000000u,  1250000u },
    { 0x5u,  1250000u,  1500000u }, { 0x6u,  1500000u,  1750000u },
    { 0x7u,  1750000u,  2100000u }, { 0xBu,  7500000u, 10000000u },
    { 0xCu, 10000000u, 12500000u }, { 0xDu, 12500000u, 15000000u },
    { 0xEu, 15000000u, 17500000u }, { 0xFu, 17500000u, 21000000u },
};

inline bool Omap3530DpllFreqSelCovers(uint32_t freqsel, uint64_t fref_hz, uint64_t n) {
    for (const auto& b : kOmap3530DpllFreqSelBands) {
        if (b.sel == freqsel && b.lo_hz * (n + 1u) <= fref_hz && fref_hz <= b.hi_hz * (n + 1u)) {
            return true;
        }
    }
    return false;
}

/* SPRUF98Y §4.7.3.3 (printed p. 307): CLKOUTX2 = (Fref x 2 x M) / (N + 1); "When M is set
   to 0 or 1, the DPLL is forced to bypass mode." Tables 4-120 (p. 440), 4-192 (p. 475):
   MULT [18:8], DIV [6:0]; Tables 4-112 (p. 438), 4-178 (p. 467): EN 0x7 lock mode. */
inline const char* Omap3530DpllClkoutX2(uint64_t fref_hz, uint32_t en, uint32_t freqsel,
                                        uint32_t mult_div, uint64_t& num, uint64_t& den) {
    const uint64_t m = (mult_div >> 8) & 0x7FFu;
    const uint64_t n = mult_div & 0x7Fu;
    if (fref_hz == 0u) return "has a 0 Hz reference clock";
    if (en != 0x7u) return "is not in lock mode";
    if (m <= 1u) return "has MULT 0 or 1, which forces bypass";
    if (!Omap3530DpllFreqSelCovers(freqsel, fref_hz, n)) {
        return "has a FREQSEL that does not cover its reference frequency";
    }
    num = fref_hz * 2u * m;
    den = n + 1u;
    return nullptr;
}
