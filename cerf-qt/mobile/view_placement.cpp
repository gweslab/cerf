#include "view_placement.h"

#include <algorithm>
#include <cmath>
#include <initializer_list>

namespace {

constexpr double kSnapScale    = 0.05;
constexpr double kSnapDistance = 0.04;
constexpr double kMinScale     = 0.05;
constexpr double kMaxScale     = 40.0;

QRectF ScreenOf(const ViewArea& a) {
    return QRectF(a.hud_left, a.hud_top, a.width - a.hud_left - a.hud_right, a.height - a.hud_top - a.hud_bottom);
}

QRectF SafeOf(const ViewArea& a) {
    const int left   = std::max(a.left, a.hud_left);
    const int top    = std::max(a.top, a.hud_top);
    const int right  = std::max(a.right, a.hud_right);
    const int bottom = std::max(a.bottom, a.hud_bottom);
    return QRectF(left, top, a.width - left - right, a.height - top - bottom);
}

double MovedAxis(double position, double extent, double old_start, double old_length, double new_start,
                 double new_length) {
    if (extent <= new_length) return new_start + (new_length - extent) / 2.0;
    const double old_centre = old_start + old_length / 2.0;
    return new_start + new_length / 2.0 - (old_centre - position);
}

}

void ViewPlacement::SetArea(const ViewArea& area) {
    if (area == area_) return;
    const ViewArea from = area_;
    area_               = area;
    if (mode_ == ViewMode::FreeForm && from.width > 0 && from.height > 0) free_ = Moved(free_, from);
}

void ViewPlacement::SetSurface(uint32_t width, uint32_t height) {
    surface_w_ = width;
    surface_h_ = height;
}

void ViewPlacement::SetMode(ViewMode mode) { mode_ = mode; }

Placement ViewPlacement::Current() const { return mode_ == ViewMode::FreeForm ? free_ : ForMode(mode_); }

QRectF ViewPlacement::ScreenRegion() const { return ScreenOf(area_); }

Placement ViewPlacement::Fit(const QRectF& region) const {
    Placement p;
    if (surface_w_ <= 0.0 || surface_h_ <= 0.0 || region.width() <= 0.0 || region.height() <= 0.0) return p;
    p.scale = std::min(region.width() / surface_w_, region.height() / surface_h_);
    p.x     = region.left() + (region.width() - surface_w_ * p.scale) / 2.0;
    p.y     = region.top() + (region.height() - surface_h_ * p.scale) / 2.0;
    return p;
}

Placement ViewPlacement::ForMode(ViewMode mode) const {
    switch (mode) {
        case ViewMode::FitScreen:
            return Fit(ScreenOf(area_));
        case ViewMode::FitSafeZone:
            return Fit(SafeOf(area_));
        case ViewMode::OriginalScale: {
            const QRectF region = ScreenOf(area_);
            return Placement{1.0, region.left() + (region.width() - surface_w_) / 2.0,
                             region.top() + (region.height() - surface_h_) / 2.0};
        }
        case ViewMode::FreeForm:
            return free_;
    }
    return free_;
}

bool ViewPlacement::Near(const Placement& a, const Placement& b) const {
    if (!NearScale(a, b)) return false;
    const double reach = kSnapDistance * std::min(area_.width, area_.height);
    const double acx   = a.x + surface_w_ * a.scale / 2.0;
    const double acy   = a.y + surface_h_ * a.scale / 2.0;
    const double bcx   = b.x + surface_w_ * b.scale / 2.0;
    const double bcy   = b.y + surface_h_ * b.scale / 2.0;
    return std::fabs(acx - bcx) <= reach && std::fabs(acy - bcy) <= reach;
}

void ViewPlacement::BeginPinch(QPointF centroid, double distance) {
    pinch_base_       = Current();
    pinch_centroid_   = centroid;
    pinch_distance_   = std::max(distance, 1.0);
    pinch_start_mode_ = mode_;
    pinch_left_       = false;
}

void ViewPlacement::UpdatePinch(QPointF centroid, double distance) {
    const double ratio = std::max(distance, 1.0) / pinch_distance_;
    Placement    next;
    next.scale            = std::clamp(pinch_base_.scale * ratio, kMinScale, kMaxScale);
    const bool zooming_out = next.scale < pinch_base_.scale;
    if (zooming_out) {
        next = Centered(next.scale);
    } else {
        const double grown = next.scale / pinch_base_.scale;
        next.x             = centroid.x() - (pinch_centroid_.x() - pinch_base_.x) * grown;
        next.y             = centroid.y() - (pinch_centroid_.y() - pinch_base_.y) * grown;
    }
    for (ViewMode snap : {ViewMode::OriginalScale, ViewMode::FitSafeZone, ViewMode::FitScreen}) {
        const Placement target = ForMode(snap);
        if (zooming_out ? !NearScale(next, target) : !Near(next, target)) continue;
        mode_       = snap;
        pinch_left_ = pinch_left_ || mode_ != pinch_start_mode_;
        return;
    }
    mode_       = ViewMode::FreeForm;
    free_       = next;
    pinch_left_ = pinch_left_ || mode_ != pinch_start_mode_;
}

Placement ViewPlacement::Centered(double scale) const {
    const QRectF region = SafeOf(area_);
    return Placement{scale, region.left() + (region.width() - surface_w_ * scale) / 2.0,
                     region.top() + (region.height() - surface_h_ * scale) / 2.0};
}

Placement ViewPlacement::Moved(const Placement& placement, const ViewArea& from) const {
    Placement    moved  = placement;
    const QRectF before = SafeOf(from);
    const QRectF after  = SafeOf(area_);
    moved.x = MovedAxis(placement.x, surface_w_ * placement.scale, before.left(), before.width(), after.left(),
                        after.width());
    moved.y = MovedAxis(placement.y, surface_h_ * placement.scale, before.top(), before.height(), after.top(),
                        after.height());
    return moved;
}

bool ViewPlacement::NearScale(const Placement& a, const Placement& b) const {
    return b.scale > 0.0 && std::fabs(a.scale / b.scale - 1.0) <= kSnapScale;
}
