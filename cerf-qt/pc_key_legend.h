#pragma once

#include <cstdint>
#include <string_view>

namespace cerffrontend {

const char* PcKeyLegend(uint8_t vk);
bool        PcLegendKey(std::string_view legend, uint8_t& vk);
bool        SameKeyName(std::string_view a, std::string_view b);

}
