#pragma once

#include <cerfcore/core/device_config_keys.h>
#include <cerfcore/core/emulation_multiplier.h>

#include <array>
#include <optional>

inline constexpr std::array<const char*, 2> kMultiplierKeys = {cerfcore::config_key::kThrottleMultiplier,
                                                               cerfcore::config_key::kCpuRateMultiplier};
inline constexpr double kDefaultMultiplier = cerfcore::EmulationMultiplier{}.Value();

inline constexpr std::array<std::optional<double>, 16> kMultiplierSteps = {
    0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8, 0.9, std::nullopt, 1.5, 2, 3, 4, 5, 10};
