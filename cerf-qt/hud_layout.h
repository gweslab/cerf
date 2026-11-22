#pragma once

#include "view_presentation.h"

#include <cerfcore/core/hud_database.h>

#include <vector>

namespace cerffrontend {

struct HudPlaced {
    const cerfcore::HudNode* node = nullptr;
    FrameRect                rect;
};

struct HudArrangement {
    std::vector<HudPlaced> elements;
};

enum class HudTurn { kNone, kClockwise, kCounterClockwise };

struct HudPanelPlace {
    FrameRect         rect;
    double            slot_lo = 0.0;
    double            slot_hi = 0.0;
    cerfcore::HudSide side    = cerfcore::HudSide::kBottom;
    HudTurn           turn    = HudTurn::kNone;
};

struct HudFrame {
    double                                 width  = 0.0;
    double                                 height = 0.0;
    bool                                   inside = false;
    const std::vector<cerfcore::HudPanel>* panels = nullptr;
    std::vector<HudPanelPlace>             places;
};

struct HudInsets {
    double top    = 0.0;
    double right  = 0.0;
    double bottom = 0.0;
    double left   = 0.0;
};

bool           HudAlongX(cerfcore::HudSide side);
double         HudAligned(cerfcore::HudAlign align, double span, double extent);
void           HudAddToSide(HudInsets& insets, cerfcore::HudSide side, double value);
double         HudOnSide(const HudInsets& insets, cerfcore::HudSide side);
HudInsets      HudEdgeDepths(const std::vector<cerfcore::HudPanel>& panels);
HudFrame       HudOutside(const cerfcore::DbHud& hud, double fb_w, double fb_h, const cerfcore::DbLcdPanelSize& units);
ContentBox     HudBox(const cerfcore::DbHud& hud, double fb_w, double fb_h);
void           HudSurfaceFor(const cerfcore::DbHud& hud, double content_w, double content_h, double& fb_w, double& fb_h);
HudArrangement HudArrange(const HudFrame& frame);
HudArrangement HudArrangePanel(const cerfcore::HudNode& root, const FrameRect& rect, HudTurn turn);

bool HudIsControl(const cerfcore::HudNode& node);
bool HudIsKeycap(const cerfcore::HudNode& node);

template <typename Placed, typename Counts, typename Side>
double HudSmallest(const std::vector<Placed>& placed, Counts counts, Side side) {
    double smallest = 0.0;
    for (const Placed& p : placed) {
        if (!counts(*p.node)) continue;
        const double s = side(p);
        if (smallest == 0.0 || s < smallest) smallest = s;
    }
    return smallest;
}

}
