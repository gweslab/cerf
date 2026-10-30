#include "view_presentation.h"

#include "hud_layout.h"

#include <algorithm>
#include <cmath>

namespace cerffrontend {

ContentBox ContentFrame::Box(double width, double height) const {
    return hud == nullptr ? ContentBox{} : HudBox(*hud, width, height);
}

void ContentFrame::SurfaceFor(double content_w, double content_h, double& surface_w, double& surface_h) const {
    if (hud != nullptr) return HudSurfaceFor(*hud, content_w, content_h, surface_w, surface_h);
    surface_w = content_w;
    surface_h = content_h;
}

ContentBox ViewPresentation::PresentedBox(double surface_w, double surface_h) const {
    const ContentBox b = frame.Box(surface_w, surface_h);
    switch (quarter & 3) {
        case 1:  return {1.0 - b.bottom, b.left, 1.0 - b.top, b.right};
        case 2:  return {1.0 - b.right, 1.0 - b.bottom, 1.0 - b.left, 1.0 - b.top};
        case 3:  return {b.top, 1.0 - b.right, b.bottom, 1.0 - b.left};
        default: return b;
    }
}

FramePoint FramePlacement::ToCanvas(FramePoint d) const {
    const double x = presented_.x;
    const double y = presented_.y;
    switch (quarter_) {
        case 1:  return {x + DeviceHeight() - d.y, y + d.x};
        case 2:  return {x + DeviceWidth() - d.x, y + DeviceHeight() - d.y};
        case 3:  return {x + d.y, y + DeviceWidth() - d.x};
        default: return {x + d.x, y + d.y};
    }
}

FramePoint FramePlacement::ToDevice(FramePoint c) const {
    const double rx = c.x - presented_.x;
    const double ry = c.y - presented_.y;
    switch (quarter_) {
        case 1:  return {ry, DeviceHeight() - rx};
        case 2:  return {DeviceWidth() - rx, DeviceHeight() - ry};
        case 3:  return {DeviceWidth() - ry, rx};
        default: return {rx, ry};
    }
}

FrameRect FramePlacement::ToCanvas(FrameRect d) const {
    const FramePoint a = ToCanvas(FramePoint{d.x, d.y});
    const FramePoint b = ToCanvas(FramePoint{d.x + d.w, d.y + d.h});
    return {std::min(a.x, b.x), std::min(a.y, b.y), std::abs(b.x - a.x), std::abs(b.y - a.y)};
}

FramePoint FramePlacement::TurnDelta(FramePoint c) const {
    switch (quarter_) {
        case 1:  return {c.y, -c.x};
        case 2:  return {-c.x, -c.y};
        case 3:  return {-c.y, c.x};
        default: return c;
    }
}

}
