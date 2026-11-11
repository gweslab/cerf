#include "hud_screen_layout.h"

#include <algorithm>
#include <bit>
#include <cstdint>

namespace cerffrontend {

namespace {

using cerfcore::DbHud;
using cerfcore::DbLcdPanelSize;
using cerfcore::HudNode;
using cerfcore::HudPanel;
using cerfcore::HudSide;

constexpr double kFingerDp = 64.0;

struct Slot {
    HudSide side   = HudSide::kBottom;
    bool    turned = false;
    double  along  = 0.0;
    double  depth  = 0.0;
    double  gap    = 0.0;
};

struct Fit {
    double scale       = 0.0;
    double framebuffer = 0.0;
};

bool HasDpad(const HudNode& node, bool full) {
    if (node.kind == HudNode::Kind::kDpad) return !full || (!node.dpad.left.empty() && !node.dpad.right.empty());
    return std::any_of(node.children.begin(), node.children.end(),
                       [full](const HudNode& child) { return HasDpad(child, full); });
}

bool KeyMatrix(const HudNode& root) {
    return root.kind == HudNode::Kind::kColumn && root.children.size() >= 2 &&
           std::all_of(root.children.begin(), root.children.end(),
                       [](const HudNode& child) { return child.kind == HudNode::Kind::kRow; });
}

bool CanCross(const HudNode& root) {
    if (!KeyMatrix(root)) return true;
    size_t longest = 0;
    for (const HudNode& row : root.children) longest = std::max(longest, row.children.size());
    return root.children.size() >= longest;
}

Slot NativeSlot(const DbHud& hud, const HudPanel& panel, const DbLcdPanelSize& units) {
    const bool   x_edge = HudAlongX(panel.side);
    const double edge   = x_edge ? units.width : units.height;
    return {panel.side, false, (x_edge ? panel.width : panel.height) * edge,
            (x_edge ? panel.height : panel.width) * edge, hud.gap * edge};
}

bool IsRocker(const HudNode& node) {
    return node.kind == HudNode::Kind::kDpad && node.dpad.left.empty() && node.dpad.right.empty();
}

double RockerDepth(const HudNode& root, double along, double depth, double gap) {
    const HudArrangement at   = HudArrangePanel(root, FrameRect{0.0, 0.0, along, depth}, gap, true);
    const HudArrangement more = HudArrangePanel(root, FrameRect{0.0, 0.0, along, depth + 1.0}, gap, true);
    double               need = depth;
    for (size_t i = 0; i < at.elements.size(); ++i) {
        const FrameRect& cell = at.elements[i].rect;
        if (!IsRocker(*at.elements[i].node) || cell.h >= cell.w) continue;
        need = std::max(need, depth + (cell.w - cell.h) / (more.elements[i].rect.h - cell.h));
    }
    return need;
}

Slot Crossed(Slot slot, HudSide side, const HudNode& root) {
    slot.side   = side;
    slot.turned = !KeyMatrix(root);
    if (slot.turned && HudAlongX(side)) slot.depth = RockerDepth(root, slot.along, slot.depth, slot.gap);
    return slot;
}

int PrimaryPanel(const std::vector<HudPanel>& panels) {
    for (size_t i = 0; i < panels.size(); ++i)
        if (HasDpad(panels[i].root, true)) return static_cast<int>(i);
    return -1;
}

class ScreenPlanner {
public:
    ScreenPlanner(const DbHud& hud, double area_w, double area_h, double fb_w, double fb_h, double finger_px)
        : hud_(hud), area_w_(area_w), area_h_(area_h), fb_w_(fb_w), fb_h_(fb_h), finger_px_(finger_px),
          primary_(PrimaryPanel(hud.panels)) {}

    std::vector<Slot> Portrait(std::vector<Slot> slots) const {
        for (size_t i = 0; i < slots.size(); ++i) {
            const HudNode& root    = hud_.panels[i].root;
            const bool     primary = static_cast<int>(i) == primary_;
            if (HudAlongX(slots[i].side)) {
                if (primary) slots[i].side = HudSide::kBottom;
                continue;
            }
            if (!CanCross(root)) continue;
            slots[i] = Crossed(slots[i], primary || HasDpad(root, false) ? HudSide::kBottom : HudSide::kTop, root);
        }
        return slots;
    }

    std::vector<Slot> Landscape(const std::vector<Slot>& slots) const {
        std::vector<size_t> movable;
        for (size_t i = 0; i < slots.size(); ++i)
            if (HudAlongX(slots[i].side) && CanCross(hud_.panels[i].root)) movable.push_back(i);
        std::vector<Slot> best       = slots;
        double            best_fit   = Measure(best).framebuffer;
        int               best_moves = 0;
        for (uint32_t mask = 1; mask < (1u << movable.size()); ++mask) {
            std::vector<Slot> trial = slots;
            for (size_t bit = 0; bit < movable.size(); ++bit) {
                if ((mask & (1u << bit)) == 0) continue;
                const size_t i = movable[bit];
                trial[i] = Crossed(slots[i], slots[i].side == HudSide::kTop ? HudSide::kLeft : HudSide::kRight,
                                   hud_.panels[i].root);
            }
            const double fit   = Measure(trial).framebuffer;
            const int    moves = std::popcount(mask);
            if (fit < best_fit || (fit == best_fit && moves >= best_moves)) continue;
            best       = std::move(trial);
            best_fit   = fit;
            best_moves = moves;
        }
        return best;
    }

    Fit Measure(const std::vector<Slot>& slots) const {
        const HudInsets depth    = Depths(slots, 1.0);
        const double    across_x = depth.left + depth.right;
        const double    across_y = depth.top + depth.bottom;
        const double    shared   = std::min(area_w_ / (fb_w_ + across_x), area_h_ / (fb_h_ + across_y));
        double       scale    = finger_px_ / SmallestControl(slots);
        if (across_x > 0.0) scale = std::min(scale, (area_w_ - shared * fb_w_) / across_x);
        if (across_y > 0.0) scale = std::min(scale, (area_h_ - shared * fb_h_) / across_y);
        for (const Slot& slot : slots)
            scale = std::min(scale, HudAlongX(slot.side) ? area_w_ / slot.along : area_h_ / (slot.along + across_y));
        return {scale, std::min((area_w_ - across_x * scale) / fb_w_, (area_h_ - across_y * scale) / fb_h_)};
    }

    std::vector<HudPanelPlace> Lay(const std::vector<Slot>& slots, double scale) const {
        const HudInsets     depth = Depths(slots, scale);
        std::vector<size_t> outward;
        for (size_t i = 0; i < slots.size(); ++i)
            if (static_cast<int>(i) != primary_) outward.push_back(i);
        if (primary_ >= 0) outward.push_back(static_cast<size_t>(primary_));
        HudInsets                  offset;
        std::vector<HudPanelPlace> out(slots.size());
        for (auto it = outward.rbegin(); it != outward.rend(); ++it) {
            const Slot&  slot   = slots[*it];
            const double d      = slot.depth * scale;
            const double along  = slot.along * scale;
            const bool   x_edge = HudAlongX(slot.side);
            const double lo     = x_edge ? 0.0 : depth.top;
            const double hi     = x_edge ? area_w_ : area_h_ - depth.bottom;
            const double at     = lo + HudAligned(cerfcore::HudAlign::kCenter, hi - lo, along);
            const double off    = HudOnSide(offset, slot.side);
            FrameRect    r;
            switch (slot.side) {
                case HudSide::kTop:    r = {at, off, along, d}; break;
                case HudSide::kBottom: r = {at, area_h_ - off - d, along, d}; break;
                case HudSide::kLeft:   r = {off, at, d, along}; break;
                case HudSide::kRight:  r = {area_w_ - off - d, at, d, along}; break;
            }
            HudAddToSide(offset, slot.side, d);
            out[*it] = {r, lo, hi, slot.side, slot.turned, slot.gap * scale};
        }
        return out;
    }

private:
    static HudInsets Depths(const std::vector<Slot>& slots, double scale) {
        HudInsets depth;
        for (const Slot& slot : slots) HudAddToSide(depth, slot.side, slot.depth * scale);
        return depth;
    }

    double SmallestControl(const std::vector<Slot>& slots) const {
        const HudFrame unit{area_w_, area_h_, true, &hud_.panels, Lay(slots, 1.0)};
        double         smallest = 0.0;
        for (const HudPlaced& placed : HudArrange(unit).elements) {
            if (placed.node->kind == HudNode::Kind::kSticker) continue;
            const double side = std::min(placed.rect.w, placed.rect.h);
            if (smallest == 0.0 || side < smallest) smallest = side;
        }
        return smallest;
    }

    const DbHud& hud_;
    double       area_w_;
    double       area_h_;
    double       fb_w_;
    double       fb_h_;
    double       finger_px_;
    int          primary_;
};

}

HudFrame HudInside(const DbHud& hud, double area_w, double area_h, int quarter, double fb_w, double fb_h,
                   const HudScreenMetrics& metrics) {
    const std::optional<DbLcdPanelSize>& board = metrics.board_screen;
    const DbLcdPanelSize& units = board ? hud.ScreenFor(board->width, board->height) : hud.ScreenFor(fb_w, fb_h);
    const double          wide  = board ? units.width : fb_w;
    const double          tall  = board ? units.height : fb_h;
    const bool            turned = (quarter & 1) != 0;
    const ScreenPlanner   planner(hud, area_w, area_h, turned ? tall : wide, turned ? wide : tall,
                                  kFingerDp * metrics.px_per_dp);
    std::vector<Slot>   slots;
    for (const HudPanel& panel : hud.panels) slots.push_back(NativeSlot(hud, panel, units));
    const std::vector<Slot> chosen = area_h > area_w ? planner.Portrait(slots) : planner.Landscape(slots);
    return {area_w, area_h, true, &hud.panels, planner.Lay(chosen, planner.Measure(chosen).scale)};
}

HudInsets HudInsideInsets(const HudFrame& frame) {
    HudInsets insets;
    for (const HudPanelPlace& place : frame.places)
        HudAddToSide(insets, place.side, HudAlongX(place.side) ? place.rect.h : place.rect.w);
    return insets;
}

}
