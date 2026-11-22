#pragma once

#include <cstdint>

#include <string>
#include <variant>

namespace cerffrontend {

struct ResourceIcon {
    std::string name;
};

struct PowerInputIcon {
    bool failed = false;
};

enum class BatteryLevel : uint8_t { kHigh, kLow, kCritical };

struct BatteryIcon {
    int          fill_percent = 0;
    bool         on_battery   = false;
    BatteryLevel level        = BatteryLevel::kHigh;
};

struct FolderIcon {
    bool enabled = false;
};

using BarIcon = std::variant<ResourceIcon, PowerInputIcon, BatteryIcon, FolderIcon>;

}
