#pragma once

#include <cstdint>

namespace cerffrontend {

struct Rgb {
    uint8_t r = 0;
    uint8_t g = 0;
    uint8_t b = 0;
    bool operator==(const Rgb&) const = default;
};

}
