#pragma once

#include <cstdint>

namespace cerffrontend {

inline constexpr uint32_t kAaudioMinRateHz = 8000u;

uint32_t AaudioRateMultiple(uint32_t rate_hz);

}
