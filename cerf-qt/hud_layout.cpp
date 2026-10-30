#include "hud_layout.h"

#include <algorithm>

namespace cerffrontend {

namespace {

using cerfcore::DbHud;
using cerfcore::HudAlign;
using cerfcore::HudNode;
using cerfcore::HudPanel;
using cerfcore::HudSide;

constexpr int kSideCount = 4;

bool AlongX(HudSide side) { return side == HudSide::kTop || side == HudSide::kBottom; }

double Base(const HudFrame& frame, HudSide side) { return AlongX(side) ? frame.base_x : frame.base_y; }

double Aligned(HudAlign align, double span, double extent) {
    switch (align) {
        case HudAlign::kStart: return 0.0;
        case HudAlign::kEnd:   return span - extent;
        default:               return (span - extent) / 2.0;
    }
}

void Place(const HudNode& node, FrameRect rect, double gap, HudArrangement& out) {
    if (node.kind == HudNode::Kind::kButton || node.kind == HudNode::Kind::kDpad) {
        out.elements.push_back({&node, rect});
        return;
    }
    if (node.kind == HudNode::Kind::kSpace || node.children.empty()) return;
    const bool row   = node.kind == HudNode::Kind::kRow;
    double     total = 0.0;
    for (const HudNode& child : node.children) total += child.grow;
    const double span = (row ? rect.w : rect.h) - gap * static_cast<double>(node.children.size() - 1);
    double       at   = row ? rect.x : rect.y;
    for (size_t i = 0; i < node.children.size(); ++i) {
        const HudNode& child  = node.children[i];
        const double   extent = span * child.grow / total;
        Place(child, row ? FrameRect{at, rect.y, extent, rect.h} : FrameRect{rect.x, at, rect.w, extent}, gap, out);
        at += extent + gap;
        if (i + 1 == node.children.size()) continue;
        const double line = at - gap / 2.0;
        out.separators.push_back(row ? HudSeparator{{line, rect.y}, {line, rect.y + rect.h}}
                                     : HudSeparator{{rect.x, line}, {rect.x + rect.w, line}});
    }
}

struct PanelSpan {
    double depth = 0.0;
    double along = 0.0;
};

void AddToSide(HudInsets& insets, HudSide side, double value) {
    switch (side) {
        case HudSide::kTop:    insets.top += value; break;
        case HudSide::kBottom: insets.bottom += value; break;
        case HudSide::kLeft:   insets.left += value; break;
        case HudSide::kRight:  insets.right += value; break;
    }
}

std::vector<PanelSpan> OutsideSpans(const HudFrame& frame) {
    const std::vector<HudPanel>& panels = *frame.panels;
    std::vector<PanelSpan>       out(panels.size());
    HudInsets                    grown;
    for (size_t i = 0; i < panels.size(); ++i) {
        const HudPanel& panel  = panels[i];
        const bool      x_edge = AlongX(panel.side);
        const double    base   = Base(frame, panel.side);
        const double    cross  = x_edge ? grown.left + grown.right : grown.top + grown.bottom;
        out[i].depth           = (x_edge ? panel.height : panel.width) * base;
        out[i].along           = (x_edge ? panel.width : panel.height) * (base + cross);
        AddToSide(grown, panel.side, out[i].depth);
    }
    return out;
}

std::vector<double> PanelDepths(const HudFrame& frame, const std::vector<PanelSpan>& spans) {
    const std::vector<HudPanel>& panels = *frame.panels;
    std::vector<double>          depth(spans.size());
    double                       total_x = 0.0, total_y = 0.0;
    for (size_t i = 0; i < spans.size(); ++i) {
        depth[i] = spans[i].depth;
        (AlongX(panels[i].side) ? total_y : total_x) += depth[i];
    }
    if (!frame.inside) return depth;
    const double free_x = frame.width - frame.base_x - total_x;
    const double free_y = frame.height - frame.base_y - total_y;
    double       rest_w = frame.width, rest_h = frame.height;
    for (size_t i = spans.size(); i-- > 0;) {
        const bool   x_edge  = AlongX(panels[i].side);
        const double stretch = (x_edge ? rest_w : rest_h) / spans[i].along;
        const double room    = depth[i] + (x_edge ? free_y : free_x) * depth[i] / (x_edge ? total_y : total_x);
        depth[i]             = std::min(depth[i] * std::max(stretch, 1.0), room);
        (x_edge ? rest_h : rest_w) -= depth[i];
    }
    return depth;
}

}

HudInsets HudEdgeDepths(const std::vector<HudPanel>& panels) {
    HudInsets depths;
    for (const HudPanel& panel : panels) {
        switch (panel.side) {
            case HudSide::kTop:    depths.top += panel.height; break;
            case HudSide::kBottom: depths.bottom += panel.height; break;
            case HudSide::kLeft:   depths.left += panel.width; break;
            case HudSide::kRight:  depths.right += panel.width; break;
        }
    }
    return depths;
}

HudFrame HudOutside(const DbHud& hud, double fb_w, double fb_h, const cerfcore::DbLcdPanelSize& units) {
    return {fb_w, fb_h, double(units.width), double(units.height), false, &hud.panels};
}

HudFrame HudInside(const DbHud& hud, double area_w, double area_h, const cerfcore::DbLcdPanelSize& units) {
    const std::vector<HudPanel>& panels = hud.InsidePanels(area_w, area_h);
    const HudInsets              depths = HudEdgeDepths(panels);
    const double                 w      = units.width;
    const double                 h      = units.height;
    const double                 scale  = std::min(area_w / (w + (depths.left + depths.right) * h),
                                                   area_h / (h + (depths.top + depths.bottom) * w));
    return {area_w, area_h, w * scale, h * scale, true, &panels};
}

HudInsets HudInsideInsets(const HudFrame& frame) {
    const std::vector<double> depth = PanelDepths(frame, OutsideSpans(frame));
    HudInsets                 insets;
    for (size_t i = 0; i < depth.size(); ++i) AddToSide(insets, (*frame.panels)[i].side, depth[i]);
    return insets;
}

ContentBox HudBox(const DbHud& hud, double fb_w, double fb_h) {
    if (fb_w <= 0.0 || fb_h <= 0.0) return {};
    double lo_x = 0.0, lo_y = 0.0, hi_x = fb_w, hi_y = fb_h;
    for (const HudPanelPlace& place : HudPanelPlaces(HudOutside(hud, fb_w, fb_h, hud.ScreenFor(fb_w, fb_h)))) {
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

HudInsets HudCanvasInsets(const HudInsets& device, int quarter) {
    const double clockwise[kSideCount] = {device.top, device.right, device.bottom, device.left};
    double       canvas[kSideCount]    = {};
    for (int side = 0; side < kSideCount; ++side) canvas[(side + quarter) & 3] = clockwise[side];
    return {canvas[0], canvas[1], canvas[2], canvas[3]};
}

std::vector<HudPanelPlace> HudPanelPlaces(const HudFrame& frame) {
    const std::vector<HudPanel>&  panels = *frame.panels;
    const size_t                  count  = panels.size();
    const std::vector<PanelSpan>  spans  = OutsideSpans(frame);
    const std::vector<double>     depth  = PanelDepths(frame, spans);
    std::vector<HudPanelPlace>    out(count);
    HudInsets                     grown;
    for (size_t i = 0; i < count; ++i) {
        const HudPanel& panel  = panels[i];
        const bool      x_edge = AlongX(panel.side);
        const double    along  = spans[i].along;
        const double    cross  = x_edge ? grown.left + grown.right : grown.top + grown.bottom;
        const double    span   = (x_edge ? frame.width : frame.height) + cross;
        const double    lo     = -(x_edge ? grown.left : grown.top);
        const double    at     = lo + Aligned(panel.align, span, along);
        out[i].slot_lo         = lo;
        out[i].slot_hi         = lo + span;
        FrameRect& r           = out[i].rect;
        switch (panel.side) {
            case HudSide::kBottom: r = {at, frame.height + grown.bottom, along, depth[i]}; break;
            case HudSide::kTop:    r = {at, -grown.top - depth[i], along, depth[i]}; break;
            case HudSide::kRight:  r = {frame.width + grown.right, at, depth[i], along}; break;
            case HudSide::kLeft:   r = {-grown.left - depth[i], at, depth[i], along}; break;
        }
        AddToSide(grown, panel.side, depth[i]);
    }
    if (!frame.inside) return out;

    FrameRect rest{0.0, 0.0, frame.width, frame.height};
    for (size_t i = count; i-- > 0;) {
        const HudPanel& panel  = panels[i];
        const double    d      = depth[i];
        const bool      x_edge = AlongX(panel.side);
        const double    len    = x_edge ? rest.w : rest.h;
        out[i].slot_lo         = x_edge ? rest.x : rest.y;
        out[i].slot_hi         = out[i].slot_lo + len;
        FrameRect& r           = out[i].rect;
        switch (panel.side) {
            case HudSide::kBottom:
                r = {rest.x, rest.y + rest.h - d, len, d};
                rest.h -= d;
                break;
            case HudSide::kTop:
                r = {rest.x, rest.y, len, d};
                rest.y += d;
                rest.h -= d;
                break;
            case HudSide::kRight:
                r = {rest.x + rest.w - d, rest.y, d, len};
                rest.w -= d;
                break;
            case HudSide::kLeft:
                r = {rest.x, rest.y, d, len};
                rest.x += d;
                rest.w -= d;
                break;
        }
    }
    return out;
}

HudArrangement HudArrange(const DbHud& hud, const HudFrame& frame) {
    HudArrangement                   out;
    const std::vector<HudPanel>&     panels = *frame.panels;
    const std::vector<HudPanelPlace> places = HudPanelPlaces(frame);
    for (size_t i = 0; i < places.size(); ++i) {
        const FrameRect& r   = places[i].rect;
        const double     gap = hud.gap * Base(frame, panels[i].side);
        Place(panels[i].root, FrameRect{r.x + gap, r.y + gap, r.w - 2.0 * gap, r.h - 2.0 * gap}, gap, out);
    }
    return out;
}

}
