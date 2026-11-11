#pragma once

#include "hud_layout.h"

#include <optional>

namespace cerffrontend {

struct HudScreenMetrics {
    double                                  px_per_dp = 1.0;
    std::optional<cerfcore::DbLcdPanelSize> board_screen;

    bool operator==(const HudScreenMetrics&) const = default;
};

HudFrame  HudInside(const cerfcore::DbHud& hud, double area_w, double area_h, int quarter, double fb_w, double fb_h,
                    const HudScreenMetrics& metrics);
HudInsets HudInsideInsets(const HudFrame& frame);

}
