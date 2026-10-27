#pragma once

#include "manager_windows.h"

#include <string_view>

namespace cerffrontend {

inline constexpr char kNoResetValue[]   = "none";
inline constexpr char kSoftResetValue[] = "soft";
inline constexpr char kHardResetValue[] = "hard";

GuestReset GuestResetFromValue(std::string_view value);

}
