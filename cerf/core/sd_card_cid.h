#pragma once

#include <array>
#include <cstdint>
#include <cstdlib>
#include <optional>
#include <string_view>

using SdCardCid = std::array<uint8_t, 16>;

// Raw register bytes, in display order. Do not infer identity from image data.
inline std::optional<SdCardCid> ParseSdCardCid(std::string_view text) {
    if (text.size() != 32 ||
        text.find_first_not_of("0123456789abcdefABCDEF") != std::string_view::npos)
        return std::nullopt;
    SdCardCid cid{};
    for (size_t i = 0; i < cid.size(); ++i) {
        const char byte[] = {text[2 * i], text[2 * i + 1], '\0'};
        cid[i] = static_cast<uint8_t>(std::strtoul(byte, nullptr, 16));
    }
    return cid;
}
