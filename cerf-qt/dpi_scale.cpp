#include "dpi_scale.h"

#include <cstdint>

namespace cerffrontend {

int ScaleForDpi(int value, int dpi) {
    const int64_t product = static_cast<int64_t>(value) * dpi;
    const int64_t half    = kDefaultDpi / 2;
    return static_cast<int>(product >= 0 ? (product + half) / kDefaultDpi
                                         : (product - half) / kDefaultDpi);
}

int IntegerFactorForDpi(int dpi) {
    const int factor = ScaleForDpi(1, dpi);
    return factor < 1 ? 1 : factor;
}

}
