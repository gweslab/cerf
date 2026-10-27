#pragma once

#include <cstdint>
#include <vector>

namespace cerfcore { struct GuestCursorShape; }

namespace cerffrontend {

enum class CursorPixel : uint8_t { kTransparent, kBlack, kWhite, kInvert };

struct GuestCursorPixels {
    static std::vector<CursorPixel> Decode(const cerfcore::GuestCursorShape& shape);
};

}
