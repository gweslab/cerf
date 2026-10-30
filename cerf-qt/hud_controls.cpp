#include "hud_controls.h"

#include "button_row.h"

#include <cerfcore/core/cerf_emulator.h>
#include <cerfcore/core/hud_database.h>
#include <cerfcore/host/device_buttons.h>
#include <cerfcore/host/keyboard_router.h>

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

bool AlongX(HudSide side) { return side == HudSide::kTop || side == HudSide::kBottom; }

double Outward(HudSide side) { return side == HudSide::kBottom || side == HudSide::kRight ? 1.0 : -1.0; }

struct SideReach {
    bool   used  = false;
    double lo    = 0.0;
    double hi    = 0.0;
    double reach = 0.0;
};

}

void HudControls::Place(const cerfcore::DbHud& hud, const ViewportLayout::Layout& frame) {
    if (&hud == hud_ && SameFrame(frame, frame_) && canvas_area_ == placed_area_) return;
    hud_         = &hud;
    frame_       = frame;
    placed_area_ = canvas_area_;
    shown_.clear();
    bands_.clear();
    separators_.clear();
    const cerfcore::DbLcdPanelSize& units = hud.ScreenFor(frame.surface_w, frame.surface_h);
    if (canvas_area_) {
        placement_ = FramePlacement(*canvas_area_, frame.quarter);
        Publish(hud, HudInside(hud, placement_.DeviceWidth(), placement_.DeviceHeight(), units), 1.0, 1.0);
        return;
    }
    placement_ = frame.Placement();
    Publish(hud, HudOutside(hud, frame.surface_w, frame.surface_h, units), placement_.DeviceWidth() / frame.surface_w,
            placement_.DeviceHeight() / frame.surface_h);
}

void HudControls::Publish(const cerfcore::DbHud& hud, const HudFrame& frame, double sx, double sy) {
    const auto scaled = [sx, sy](const FrameRect& r) { return FrameRect{r.x * sx, r.y * sy, r.w * sx, r.h * sy}; };
    const auto turned = [this, sx, sy](FramePoint p) { return placement_.ToCanvas(FramePoint{p.x * sx, p.y * sy}); };
    const HudArrangement arrangement = HudArrange(hud, frame);
    for (const HudPlaced& e : arrangement.elements) {
        const FrameRect device = scaled(e.rect);
        shown_.push_back({e.node, device, placement_.ToCanvas(device)});
    }
    for (const HudSeparator& s : arrangement.separators) separators_.push_back({turned(s.from), turned(s.to)});

    const double                 width  = placement_.DeviceWidth();
    const double                 height = placement_.DeviceHeight();
    const std::vector<HudPanelPlace> places = HudPanelPlaces(frame);
    SideReach                        sides[kSideCount];
    for (size_t i = 0; i < places.size(); ++i) {
        const HudSide   side     = (*frame.panels)[i].side;
        const FrameRect r        = scaled(places[i].rect);
        const bool      along    = AlongX(side);
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
    for (int i = 0; i < kSideCount; ++i) {
        const SideReach& s = sides[i];
        if (!s.used) continue;
        const HudSide side  = static_cast<HudSide>(i);
        const bool    along = AlongX(side);
        const double  out   = Outward(side);
        const double  edge  = out > 0 ? (along ? height : width) : 0.0;
        HudBandShown  band;
        band.side         = side;
        band.inner        = frame.inside ? edge - out * s.reach : edge;
        band.outer        = frame.inside ? edge : edge + out * s.reach;
        band.lo           = s.lo;
        band.hi           = s.hi;
        const double near = std::min(band.inner, band.outer);
        const double span = std::abs(band.outer - band.inner);
        band.canvas = placement_.ToCanvas(along ? FrameRect{s.lo, near, s.hi - s.lo, span}
                                                : FrameRect{near, s.lo, span, s.hi - s.lo});
        bands_.push_back(band);
    }
}

void HudControls::Clear() {
    hud_ = nullptr;
    shown_.clear();
    bands_.clear();
    separators_.clear();
}

bool HudControls::InBand(int x, int y) const {
    const double px = x + 0.5;
    const double py = y + 0.5;
    return std::any_of(bands_.begin(), bands_.end(),
                       [px, py](const HudBandShown& band) { return Contains(band.canvas, px, py); });
}

const HudShown* HudControls::At(int x, int y) const {
    const double px = x + 0.5;
    const double py = y + 0.5;
    for (const HudShown& s : shown_) {
        if (!Contains(s.canvas, px, py)) continue;
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

bool HudControls::Press(int pointer, int x, int y) {
    const HudShown* s = At(x, y);
    if (s == nullptr) return false;
    PointerPress press;
    press.node  = s->node;
    press.since = std::chrono::steady_clock::now();
    if (s->node->kind == HudNode::Kind::kButton) {
        if (Latched(s->node))                    press.unlatch = true;
        else if (!s->node->button.action.empty()) RunAction(s->node->button.action);
        else                                      press.keys = s->node->button.keys;
    } else {
        press.keys = DpadKeys(*s, placement_.ToDevice(FramePoint{x + 0.5, y + 0.5}));
    }
    PressKeys(press.keys);
    pointers_[pointer] = std::move(press);
    return true;
}

void HudControls::Move(int pointer, int x, int y) {
    const auto it = pointers_.find(pointer);
    if (it == pointers_.end() || it->second.node->kind != HudNode::Kind::kDpad) return;
    const HudShown* s = Of(it->second.node);
    if (s == nullptr) return;
    std::vector<uint8_t> keys = DpadKeys(*s, placement_.ToDevice(FramePoint{x + 0.5, y + 0.5}));
    if (keys == it->second.keys) return;
    PressKeys(keys);
    ReleaseKeys(it->second.keys);
    it->second.keys = std::move(keys);
}

void HudControls::Release(int pointer, bool hold_latches) {
    const auto it = pointers_.find(pointer);
    if (it == pointers_.end()) return;
    const PointerPress press = std::move(it->second);
    pointers_.erase(it);
    if (press.unlatch) {
        const auto latched = latched_.find(press.node);
        if (latched == latched_.end()) return;
        ReleaseKeys(latched->second);
        latched_.erase(latched);
        return;
    }
    const auto held_ms =
        std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - press.since).count();
    if (hold_latches && !press.keys.empty() && press.node->kind == HudNode::Kind::kButton &&
        held_ms >= ButtonRow::kHoldMs) {
        latched_[press.node] = press.keys;
        return;
    }
    ReleaseKeys(press.keys);
}

bool HudControls::ToggleLatch(int x, int y) {
    const HudShown* s = At(x, y);
    if (s == nullptr) return false;
    if (s->node->kind != HudNode::Kind::kButton) return true;
    if (!s->node->button.action.empty()) {
        RunAction(s->node->button.action);
        return true;
    }
    const auto latched = latched_.find(s->node);
    if (latched != latched_.end()) {
        ReleaseKeys(latched->second);
        latched_.erase(latched);
        return true;
    }
    PressKeys(s->node->button.keys);
    latched_[s->node] = s->node->button.keys;
    return true;
}

void HudControls::CancelAll() {
    for (auto& [pointer, press] : pointers_) ReleaseKeys(press.keys);
    pointers_.clear();
    for (auto& [node, keys] : latched_) ReleaseKeys(keys);
    latched_.clear();
}

bool HudControls::KeyDown(uint8_t vk) const {
    return count_[vk] != 0 || emu_.Get<cerfcore::KeyboardRouter>().Held(vk);
}

bool HudControls::Pressed(const HudNode* node) const {
    return std::any_of(pointers_.begin(), pointers_.end(), [node](const auto& p) { return p.second.node == node; });
}

void HudControls::RunAction(const std::string& id) {
    for (const cerfcore::ActionControl& action : emu_.Get<cerfcore::DeviceButtons>().Actions())
        if (action.id == id) action.press();
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
