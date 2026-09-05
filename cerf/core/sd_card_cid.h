#pragma once

#include <array>
#include <cstdint>
#include <optional>
#include <string_view>

using SdCardCid = std::array<uint8_t, 16>;

// Raw register bytes, in display order. Do not infer identity from image data.
inline std::optional<SdCardCid> ParseSdCardCid(std::string_view text) {
    if (text.size() != 32) return std::nullopt;
    const auto hex = [](char c) -> int {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'a' && c <= 'f') return c - 'a' + 10;
        if (c >= 'A' && c <= 'F') return c - 'A' + 10;
        return -1;
    };
    SdCardCid cid{};
    for (size_t i = 0; i < cid.size(); ++i) {
        const int hi = hex(text[2 * i]), lo = hex(text[2 * i + 1]);
        if (hi < 0 || lo < 0) return std::nullopt;
        cid[i] = static_cast<uint8_t>((hi << 4) | lo);
    }
    return cid;
}
