#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace cerffrontend {

inline constexpr char kHostKeyJoiner[] = "+";

std::string HostKeyComboLabel(const std::vector<uint8_t>& vks);

}
