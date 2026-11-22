#include "hud_controls.h"

#include "button_row.h"
#include "host_holds_release.h"

#include <cerfcore/core/cerf_emulator.h>
#include <cerfcore/core/hud_database.h>
#include <cerfcore/host/keyboard_router.h>
#include <cerfcore/host/machine_indicators.h>
#include <cerfcore/host/machine_object_tree.h>

#include <algorithm>
#include <cmath>

namespace cerffrontend {

REGISTER_SERVICE(HudControls);

namespace {

using cerfcore::HudDpadShape;
using cerfcore::HudNode;
using cerfcore::HudSide;

constexpr double kDpadSideThreshold = 1.0 / 3.0;
constexpr int    kSideCount         = 4;

bool SameFrame(const ViewportLayout::Layout& a, const ViewportLayout::Layout& b) {
    return a.dst_x == b.dst_x && a.dst_y == b.dst_y && a.dst_w == b.dst_w && a.dst_h == b.dst_h &&
           a.quarter == b.quarter && a.surface_w == b.surface_w && a.surface_h == b.surface_h;
}

bool Contains(const FrameRect& r, double x, double y) {
    return x >= r.x && x < r.x + r.w && y >= r.y && y < r.y + r.h;
}

void Append(std::vector<uint8_t>& out, const std::vector<uint8_t>& keys) { out.insert(out.end(), keys.begin(), keys.end()); }

double Outward(HudSide side) { return side == HudSide::kBottom || side == HudSide::kRight ? 1.0 : -1.0; }

struct SideReach {
    bool   used  = false;
    double lo    = 0.0;
    double hi    = 0.0;
    double reach = 0.0;
};

void MeasureSides(const HudFrame& frame, double width, double height, double sx, double sy,
                  SideReach (&sides)[kSideCount]) {
    const auto scaled = [sx, sy](const FrameRect& r) { return FrameRect{r.x * sx, r.y * sy, r.w * sx, r.h * sy}; };
    const std::vector<HudPanelPlace>& places = frame.places;
    for (size_t i = 0; i < places.size(); ++i) {
        const HudSide   side     = places[i].side;
        const FrameRect r        = scaled(places[i].rect);
        const bool      along    = HudAlongX(side);
        const double    slot_s   = along ? sx : sy;
        const double    out      = Outward(side);
        const double    edge     = out > 0 ? (along ? height : width) : 0.0;
        const double    cross_lo = along ? r.y : r.x;
        const double    cross_hi = cross_lo + (along ? r.h : r.w);
        const double    reach    = frame.inside ? out * (edge - (out > 0 ? cross_lo : cross_hi))
                                                : out * ((out > 0 ? cross_hi : cross_lo) - edge);
        SideReach&      s        = sides[static_cast<int>(side)];
        if (!s.used) s = {true, places[i].slot_lo * slot_s, places[i].slot_hi * slot_s, 0.0};
        s.lo    = std::min({s.lo, places[i].slot_lo * slot_s, along ? r.x : r.y});
        s.hi    = std::max({s.hi, places[i].slot_hi * slot_s, (along ? r.x : r.y) + (along ? r.w : r.h)});
        s.reach = std::max(s.reach, reach);
    }
}

std::vector<FrameRect> BandRects(const HudFrame& frame, const FramePlacement& placement, double sx, double sy) {
    const double width  = placement.DeviceWidth();
    const double height = placement.DeviceHeight();
    SideReach    sides[kSideCount];
    MeasureSides(frame, width, height, sx, sy, sides);
    std::vector<FrameRect> rects;
    for (int i = 0; i < kSideCount; ++i) {
        const SideReach& s = sides[i];
        if (!s.used) continue;
        const HudSide side  = static_cast<HudSide>(i);
        const bool    along = HudAlongX(side);
        const double  out   = Outward(side);
        const double  edge  = out > 0 ? (along ? height : width) : 0.0;
        const double  inner = frame.inside ? edge - out * s.reach : edge;
        const double  outer = frame.inside ? edge : edge + out * s.reach;
        const double  near  = std::min(inner, outer);
        const double  span  = std::abs(outer - inner);
        rects.push_back(placement.ToCanvas(along ? FrameRect{s.lo, near, s.hi - s.lo, span}
                                                 : FrameRect{near, s.lo, span, s.hi - s.lo}));
    }
    return rects;
}

double FarDistance(const FrameRect& from, const FrameRect& to) {
    const double dx = std::max({0.0, from.x - to.x, to.x + to.w - (from.x + from.w)});
    const double dy = std::max({0.0, from.y - to.y, to.y + to.h - (from.y + from.h)});
    return std::max(dx, dy);
}

}

void HudControls::OnReady() { emu_.Get<HostHoldsRelease>().Add([this] { CancelAll(); }); }

void HudControls::Place(const cerfcore::DbHud& hud, const ViewportLayout::Layout& frame) {
    if (&hud == hud_ && SameFrame(frame, frame_) && canvas_area_ == placed_area_) return;
    hud_         = &hud;
    frame_       = frame;
    placed_area_ = canvas_area_;
    shown_.clear();
    bands_.clear();
    const HudFit fit = FitFor(hud, frame);
    placement_       = fit.placement;
    Publish(fit.frame, fit.sx, fit.sy);
}

double HudControls::PanelReach(const cerfcore::DbHud& hud, const ViewportLayout::Layout& frame) const {
    const HudFit    fit   = FitFor(hud, frame);
    const FrameRect image = frame.Rect();
    double          reach = 0.0;
    for (const FrameRect& band : BandRects(fit.frame, fit.placement, fit.sx, fit.sy))
        reach = std::max(reach, FarDistance(image, band));
    return reach;
}

HudControls::HudFit HudControls::FitFor(const cerfcore::DbHud& hud, const ViewportLayout::Layout& frame) const {
    const double fb_w = frame.surface_w;
    const double fb_h = frame.surface_h;
    if (canvas_area_) {
        const FrameRect& area = canvas_area_->rect;
        return {FramePlacement(area, 0), HudInside(hud, area.w, area.h, frame.quarter, fb_w, fb_h, canvas_area_->metrics),
                1.0, 1.0};
    }
    const FramePlacement placement = frame.Placement();
    return {placement, HudOutside(hud, fb_w, fb_h, hud.ScreenFor(fb_w, fb_h)), placement.DeviceWidth() / fb_w,
            placement.DeviceHeight() / fb_h};
}

void HudControls::Publish(const HudFrame& frame, double sx, double sy) {
    const auto scaled = [sx, sy](const FrameRect& r) { return FrameRect{r.x * sx, r.y * sy, r.w * sx, r.h * sy}; };
    for (const HudPlaced& e : HudArrange(frame).elements) {
        const FrameRect device = scaled(e.rect);
        shown_.push_back({e.node, device, placement_.ToCanvas(device)});
    }
    bands_ = BandRects(frame, placement_, sx, sy);
}

void HudControls::Clear() {
    hud_ = nullptr;
    shown_.clear();
    bands_.clear();
}

bool HudControls::InBand(int x, int y) const {
    const double px = x + 0.5;
    const double py = y + 0.5;
    return std::any_of(bands_.begin(), bands_.end(),
                       [px, py](const FrameRect& band) { return Contains(band, px, py); });
}

const HudShown* HudControls::At(int x, int y) const {
    const double px = x + 0.5;
    const double py = y + 0.5;
    for (const HudShown& s : shown_) {
        if (s.node->kind == HudNode::Kind::kSticker || s.node->kind == HudNode::Kind::kIndicator ||
            !Contains(s.canvas, px, py))
            continue;
        if (s.node->kind == HudNode::Kind::kDpad && s.node->dpad.shape == HudDpadShape::kCircle) {
            const double r  = std::min(s.canvas.w, s.canvas.h) / 2.0;
            const double dx = px - (s.canvas.x + s.canvas.w / 2.0);
            const double dy = py - (s.canvas.y + s.canvas.h / 2.0);
            if (dx * dx + dy * dy > r * r) continue;
        }
        return &s;
    }
    return nullptr;
}

const HudShown* HudControls::Of(const HudNode* node) const {
    for (const HudShown& s : shown_)
        if (s.node == node) return &s;
    return nullptr;
}

bool HudControls::HitTest(int x, int y) const { return At(x, y) != nullptr; }

std::vector<uint8_t> HudControls::DpadKeys(const HudShown& shown, FramePoint device) const {
    const cerfcore::HudDpad& dpad   = shown.node->dpad;
    const FrameRect&         r      = shown.device;
    const bool               circle = dpad.shape == HudDpadShape::kCircle;
    const double             half_w = (circle ? std::min(r.w, r.h) : r.w) / 2.0;
    const double             half_h = (circle ? std::min(r.w, r.h) : r.h) / 2.0;
    const double             u      = (device.x - (r.x + r.w / 2.0)) / half_w;
    const double             v      = (device.y - (r.y + r.h / 2.0)) / half_h;
    std::vector<uint8_t>     keys;
    if (v < -kDpadSideThreshold)     Append(keys, dpad.up);
    else if (v > kDpadSideThreshold) Append(keys, dpad.down);
    if (u < -kDpadSideThreshold)     Append(keys, dpad.left);
    else if (u > kDpadSideThreshold) Append(keys, dpad.right);
    if (keys.empty()) keys = dpad.center;
    return keys;
}

bool HudControls::Press(HudPointer pointer, int x, int y) {
    if (Holds(pointer)) Release(pointer, false);
    const HudShown* s = At(x, y);
    if (s == nullptr) return false;
    PointerPress press;
    press.node  = s->node;
    press.since = std::chrono::steady_clock::now();
    if (s->node->kind == HudNode::Kind::kButton) {
        if (Latched(s->node)) press.unlatch = true;
        else                  press.held = TargetOf(s->node->button);
    } else {
        press.held.keys = DpadKeys(*s, placement_.ToDevice(FramePoint{x + 0.5, y + 0.5}));
    }
    Engage(press.held);
    pointers_[pointer] = std::move(press);
    return true;
}

void HudControls::Move(HudPointer pointer, int x, int y) {
    const auto it = pointers_.find(pointer);
    if (it == pointers_.end() || it->second.node->kind != HudNode::Kind::kDpad) return;
    const HudShown* s = Of(it->second.node);
    if (s == nullptr) return;
    std::vector<uint8_t> keys = DpadKeys(*s, placement_.ToDevice(FramePoint{x + 0.5, y + 0.5}));
    if (keys == it->second.held.keys) return;
    PressKeys(keys);
    ReleaseKeys(it->second.held.keys);
    it->second.held.keys = std::move(keys);
}

void HudControls::Release(HudPointer pointer, bool hold_latches) {
    const auto it = pointers_.find(pointer);
    if (it == pointers_.end()) return;
    const PointerPress press = std::move(it->second);
    pointers_.erase(it);
    if (press.unlatch) {
        const auto latched = latched_.find(press.node);
        if (latched == latched_.end()) return;
        Disengage(latched->second);
        latched_.erase(latched);
        return;
    }
    const auto held_ms =
        std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - press.since).count();
    if (hold_latches && press.held.Holds() && press.node->kind == HudNode::Kind::kButton &&
        held_ms >= ButtonRow::kHoldMs) {
        latched_[press.node] = press.held;
        return;
    }
    Disengage(press.held);
}

bool HudControls::ToggleLatch(int x, int y) {
    const HudShown* s = At(x, y);
    if (s == nullptr) return false;
    if (s->node->kind != HudNode::Kind::kButton) return true;
    const auto latched = latched_.find(s->node);
    if (latched != latched_.end()) {
        Disengage(latched->second);
        latched_.erase(latched);
        return true;
    }
    const HudHeld held = TargetOf(s->node->button);
    Engage(held);
    if (held.Holds()) latched_[s->node] = held;
    else              Disengage(held);
    return true;
}

void HudControls::CancelAll() {
    for (auto& [pointer, press] : pointers_) Disengage(press.held);
    pointers_.clear();
    for (auto& [node, held] : latched_) Disengage(held);
    latched_.clear();
}

bool HudControls::KeyDown(uint8_t vk) const {
    return count_[vk] != 0 || emu_.Get<cerfcore::KeyboardRouter>().Held(vk);
}

bool HudControls::Pressed(const HudNode* node) const {
    return std::any_of(pointers_.begin(), pointers_.end(), [node](const auto& p) { return p.second.node == node; });
}

bool HudControls::HudHeld::Holds() const { return !keys.empty() || (button != nullptr && !button->Momentary()); }

HudControls::HudHeld HudControls::TargetOf(const cerfcore::HudButton& button) const {
    HudHeld held;
    held.keys = button.keys;
    if (!button.action.empty())
        held.button = dynamic_cast<cerfcore::MachineButton*>(emu_.Get<cerfcore::MachineObjectTree>().Find(button.action));
    return held;
}

void HudControls::Engage(const HudHeld& held) {
    PressKeys(held.keys);
    if (held.button != nullptr) held.button->Down();
}

void HudControls::Disengage(const HudHeld& held) {
    if (held.button != nullptr) held.button->Up();
    ReleaseKeys(held.keys);
}

bool HudControls::KeysDown(const std::vector<uint8_t>& keys) const {
    return !keys.empty() && std::all_of(keys.begin(), keys.end(), [this](uint8_t vk) { return KeyDown(vk); });
}

void HudControls::PressKeys(const std::vector<uint8_t>& keys) {
    for (uint8_t vk : keys)
        if (count_[vk]++ == 0) emu_.Get<cerfcore::KeyboardRouter>().OnStockKey(vk, false);
}

void HudControls::ReleaseKeys(const std::vector<uint8_t>& keys) {
    for (auto it = keys.rbegin(); it != keys.rend(); ++it)
        if (--count_[*it] == 0) emu_.Get<cerfcore::KeyboardRouter>().OnStockKey(*it, true);
}

}
