#pragma once

#include "rgb.h"

#include <cstdint>

#include <optional>
#include <string>
#include <variant>
#include <vector>

namespace cerffrontend {

struct ResourceIcon {
    std::string name;
};

struct ChipIcon {};

struct HardDiskIcon {};

struct LampLook {
    bool               lit      = false;
    Rgb                color;
    bool               blinking = false;
    uint32_t           on_ms    = 0;
    uint32_t           off_ms   = 0;
    std::optional<Rgb> between  = std::nullopt;
};

struct LedIcon {
    std::vector<LampLook> lamps;
    bool                  vibrate = false;
};

struct LedGridCell {
    bool lit = false;
    Rgb  color;
};

struct LedGridIcon {
    std::vector<LedGridCell> cells;
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

using BarIcon = std::variant<ResourceIcon, ChipIcon, HardDiskIcon, LedIcon, LedGridIcon, PowerInputIcon,
                             BatteryIcon, FolderIcon>;

}
