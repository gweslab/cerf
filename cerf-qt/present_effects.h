#pragma once

#include <cstdint>

namespace cerffrontend {

struct PresentEffects {
    static void DesaturateAndDim(uint32_t* pixels, int count);
};

}
