#include "hud_layout.h"

#include <algorithm>

namespace cerffrontend {

namespace {

using cerfcore::DbHud;
using cerfcore::HudAlign;
using cerfcore::HudNode;
using cerfcore::HudPanel;
using cerfcore::HudSide;

bool HoldsControl(const HudNode& node) {
    switch (node.kind) {
        case HudNode::Kind::kButton:
        case HudNode::Kind::kDpad:   return true;
        case HudNode::Kind::kRow:
        case HudNode::Kind::kColumn: return std::any_of(node.children.begin(), node.children.end(), HoldsControl);
        default:                     return false;
    }
}

void Place(const HudNode& node, FrameRect rect, double gap, bool turned, HudArrangement& out) {
    if (node.kind == HudNode::Kind::kButton || node.kind == HudNode::Kind::kDpad ||
        node.kind == HudNode::Kind::kSticker) {
        out.elements.push_back({&node, rect});
        return;
    }
    if (node.kind == HudNode::Kind::kSpace || node.children.empty()) return;
    const bool row   = (node.kind == HudNode::Kind::kRow) != turned;
    double     total = 0.0;
    for (const HudNode& child : node.children) total += child.grow;
    const double pitch = ((row ? rect.w : rect.h) + gap) / total;
    double       at    = row ? rect.x : rect.y;
    for (size_t i = 0; i < node.children.size(); ++i) {
        const HudNode& child  = node.children[i];
        const double   extent = pitch * child.grow - gap;
        Place(child, row ? FrameRect{at, rect.y, extent, rect.h} : FrameRect{rect.x, at, rect.w, extent}, gap, turned,
              out);
        at += extent + gap;
        if (i + 1 == node.children.size() || !HoldsControl(child) || !HoldsControl(node.children[i + 1])) continue;
        const double line = at - gap / 2.0;
        out.separators.push_back(row ? HudSeparator{{line, rect.y}, {line, rect.y + rect.h}}
                                     : HudSeparator{{rect.x, line}, {rect.x + rect.w, line}});
    }
}

void PlacePanel(const HudNode& root, const FrameRect& rect, double gap, bool turned, HudArrangement& out) {
    Place(root, FrameRect{rect.x + gap, rect.y + gap, rect.w - 2.0 * gap, rect.h - 2.0 * gap}, gap, turned, out);
}

}

bool HudAlongX(HudSide side) { return side == HudSide::kTop || side == HudSide::kBottom; }

double HudAligned(HudAlign align, double span, double extent) {
    switch (align) {
        case HudAlign::kStart: return 0.0;
        case HudAlign::kEnd:   return span - extent;
        default:               return (span - extent) / 2.0;
    }
}

void HudAddToSide(HudInsets& insets, HudSide side, double value) {
    switch (side) {
        case HudSide::kTop:    insets.top += value; break;
        case HudSide::kBottom: insets.bottom += value; break;
        case HudSide::kLeft:   insets.left += value; break;
        case HudSide::kRight:  insets.right += value; break;
    }
}

double HudOnSide(const HudInsets& insets, HudSide side) {
    switch (side) {
        case HudSide::kTop:    return insets.top;
        case HudSide::kBottom: return insets.bottom;
        case HudSide::kLeft:   return insets.left;
        default:               return insets.right;
    }
}

HudInsets HudEdgeDepths(const std::vector<HudPanel>& panels) {
    HudInsets depths;
    for (const HudPanel& panel : panels)
        HudAddToSide(depths, panel.side, HudAlongX(panel.side) ? panel.height : panel.width);
    return depths;
}

HudFrame HudOutside(const DbHud& hud, double fb_w, double fb_h, const cerfcore::DbLcdPanelSize& units) {
    HudFrame  frame{fb_w, fb_h, false, &hud.panels, {}};
    HudInsets grown;
    for (const HudPanel& panel : hud.panels) {
        const bool    x_edge = HudAlongX(panel.side);
        const double  base   = x_edge ? units.width : units.height;
        const double  cross  = x_edge ? grown.left + grown.right : grown.top + grown.bottom;
        const double  depth  = (x_edge ? panel.height : panel.width) * base;
        const double  along  = (x_edge ? panel.width : panel.height) * (base + cross);
        const double  span   = (x_edge ? fb_w : fb_h) + cross;
        const double  lo     = -(x_edge ? grown.left : grown.top);
        const double  at     = lo + HudAligned(panel.align, span, along);
        HudPanelPlace place{{}, lo, lo + span, panel.side, false, hud.gap * base};
        switch (panel.side) {
            case HudSide::kBottom: place.rect = {at, fb_h + grown.bottom, along, depth}; break;
            case HudSide::kTop:    place.rect = {at, -grown.top - depth, along, depth}; break;
            case HudSide::kRight:  place.rect = {fb_w + grown.right, at, depth, along}; break;
            case HudSide::kLeft:   place.rect = {-grown.left - depth, at, depth, along}; break;
        }
        HudAddToSide(grown, panel.side, depth);
        frame.places.push_back(place);
    }
    return frame;
}

ContentBox HudBox(const DbHud& hud, double fb_w, double fb_h) {
    if (fb_w <= 0.0 || fb_h <= 0.0) return {};
    double lo_x = 0.0, lo_y = 0.0, hi_x = fb_w, hi_y = fb_h;
    for (const HudPanelPlace& place : HudOutside(hud, fb_w, fb_h, hud.ScreenFor(fb_w, fb_h)).places) {
        const FrameRect& r = place.rect;
        lo_x = std::min(lo_x, r.x);
        lo_y = std::min(lo_y, r.y);
        hi_x = std::max(hi_x, r.x + r.w);
        hi_y = std::max(hi_y, r.y + r.h);
    }
    return {lo_x / fb_w, lo_y / fb_h, hi_x / fb_w, hi_y / fb_h};
}

void HudSurfaceFor(const DbHud& hud, double content_w, double content_h, double& fb_w, double& fb_h) {
    const HudInsets depths = HudEdgeDepths(hud.panels);
    const auto      fits   = [&](const cerfcore::DbLcdPanelSize& units, double& w, double& h) {
        w = content_w - (depths.left + depths.right) * units.height;
        h = content_h - (depths.top + depths.bottom) * units.width;
        const cerfcore::DbLcdPanelSize& chosen = hud.ScreenFor(w, h);
        return chosen.width == units.width && chosen.height == units.height;
    };
    fb_w = fb_h = 0.0;
    for (const cerfcore::DbLcdPanelSize& units : hud.screens) {
        double w = 0.0, h = 0.0;
        if (fits(units, w, h) && w * h > fb_w * fb_h) {
            fb_w = w;
            fb_h = h;
        }
    }
    if (fb_w > 0.0 && fb_h > 0.0) return;
    fits(hud.ScreenFor(content_w, content_h), fb_w, fb_h);
}

HudArrangement HudArrange(const HudFrame& frame) {
    HudArrangement out;
    for (size_t i = 0; i < frame.places.size(); ++i) {
        const HudPanelPlace& place = frame.places[i];
        PlacePanel((*frame.panels)[i].root, place.rect, place.gap, place.turned, out);
    }
    return out;
}

HudArrangement HudArrangePanel(const HudNode& root, const FrameRect& rect, double gap, bool turned) {
    HudArrangement out;
    PlacePanel(root, rect, gap, turned, out);
    return out;
}

}
