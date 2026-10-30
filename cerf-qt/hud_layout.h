#pragma once

#include "view_presentation.h"

#include <cerfcore/core/hud_database.h>

#include <vector>

namespace cerffrontend {

struct HudPlaced {
    const cerfcore::HudNode* node = nullptr;
    FrameRect                rect;
};

struct HudSeparator {
    FramePoint from;
    FramePoint to;
};

struct HudArrangement {
    std::vector<HudPlaced>    elements;
    std::vector<HudSeparator> separators;
};

struct HudFrame {
    double                                  width  = 0.0;
    double                                  height = 0.0;
    double                                  base_x = 0.0;
    double                                  base_y = 0.0;
    bool                                    inside = false;
    const std::vector<cerfcore::HudPanel>*  panels = nullptr;
};

struct HudPanelPlace {
    FrameRect rect;
    double    slot_lo = 0.0;
    double    slot_hi = 0.0;
};

struct HudInsets {
    double top    = 0.0;
    double right  = 0.0;
    double bottom = 0.0;
    double left   = 0.0;
};

HudInsets              HudEdgeDepths(const std::vector<cerfcore::HudPanel>& panels);
HudFrame               HudOutside(const cerfcore::DbHud& hud, double fb_w, double fb_h, const cerfcore::DbLcdPanelSize& units);
HudFrame               HudInside(const cerfcore::DbHud& hud, double area_w, double area_h, const cerfcore::DbLcdPanelSize& units);
HudInsets              HudInsideInsets(const HudFrame& frame);
ContentBox             HudBox(const cerfcore::DbHud& hud, double fb_w, double fb_h);
void HudSurfaceFor(const cerfcore::DbHud& hud, double content_w, double content_h, double& fb_w, double& fb_h);
HudInsets              HudCanvasInsets(const HudInsets& device, int quarter);
std::vector<HudPanelPlace> HudPanelPlaces(const HudFrame& frame);
HudArrangement         HudArrange(const cerfcore::DbHud& hud, const HudFrame& frame);

}
