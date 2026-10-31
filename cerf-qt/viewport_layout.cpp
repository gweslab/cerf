#include "viewport_layout.h"

#include <algorithm>
#include <cmath>

namespace cerffrontend {

namespace {

int Round(double v) { return static_cast<int>(std::lround(v)); }

}

void ViewportLayout::SetSurfaceSize(uint32_t w, uint32_t h) {
    surface_w_.store(w, std::memory_order_release);
    surface_h_.store(h, std::memory_order_release);
}

int ViewportLayout::PresentedWidth() const {
    return static_cast<int>(presentation_.Turned() ? SurfaceHeight() : SurfaceWidth());
}

int ViewportLayout::PresentedHeight() const {
    return static_cast<int>(presentation_.Turned() ? SurfaceWidth() : SurfaceHeight());
}

void ViewportLayout::SetCanvasSize(int w, int h) {
    canvas_w_ = w;
    canvas_h_ = h;
}

void ViewportLayout::ContentFor(uint32_t surface_w, uint32_t surface_h, int& content_w, int& content_h) const {
    const ContentBox box = presentation_.PresentedBox(surface_w, surface_h);
    const int        f   = ScaleFactor();
    const double     pw  = presentation_.Turned() ? surface_h : surface_w;
    const double     ph  = presentation_.Turned() ? surface_w : surface_h;
    content_w            = Round(pw * box.Width() * f);
    content_h            = Round(ph * box.Height() * f);
}

int ViewportLayout::ContentWidth() const {
    int w = 0, h = 0;
    ContentFor(SurfaceWidth(), SurfaceHeight(), w, h);
    return w;
}

int ViewportLayout::ContentHeight() const {
    int w = 0, h = 0;
    ContentFor(SurfaceWidth(), SurfaceHeight(), w, h);
    return h;
}

void ViewportLayout::SurfaceFor(int content_w, int content_h, uint32_t& surface_w, uint32_t& surface_h) const {
    const int    f  = ScaleFactor();
    const double cw = static_cast<double>(presentation_.Turned() ? content_h : content_w) / f;
    const double ch = static_cast<double>(presentation_.Turned() ? content_w : content_h) / f;
    double       sw = 0.0, sh = 0.0;
    presentation_.frame.SurfaceFor(cw, ch, sw, sh);
    surface_w = static_cast<uint32_t>(std::max(0.0, std::floor(sw)));
    surface_h = static_cast<uint32_t>(std::max(0.0, std::floor(sh)));
    int fit_w = 0, fit_h = 0;
    ContentFor(surface_w + 1u, surface_h, fit_w, fit_h);
    if (fit_w <= content_w && fit_h <= content_h) ++surface_w;
    ContentFor(surface_w, surface_h + 1u, fit_w, fit_h);
    if (fit_w <= content_w && fit_h <= content_h) ++surface_h;
}

bool ViewportLayout::SetMode(ViewportMode m) {
    if (mode_ == m) return false;
    mode_ = m;
    ResetScroll();
    return true;
}

bool ViewportLayout::SetAntialias(bool on) {
    if (antialias_ == on) return false;
    antialias_ = on;
    return true;
}

bool ViewportLayout::SetIntegerScale(int factor) {
    factor = std::max(factor, 1);
    if (mode_ == ViewportMode::Integer && integer_factor_ == factor) return false;
    mode_           = ViewportMode::Integer;
    integer_factor_ = factor;
    ResetScroll();
    return true;
}

bool ViewportLayout::SetPlacement(double scale, double x, double y) {
    if (mode_ == ViewportMode::Placed && placed_scale_ == scale && placed_x_ == x && placed_y_ == y) return false;
    mode_         = ViewportMode::Placed;
    placed_scale_ = scale;
    placed_x_     = x;
    placed_y_     = y;
    return true;
}

bool ViewportLayout::SetPresentation(const ViewPresentation& presentation) {
    if (presentation_ == presentation) return false;
    presentation_ = presentation;
    ResetScroll();
    return true;
}

bool ViewportLayout::SetActive(bool active) {
    if (active_ == active) return false;
    active_ = active;
    return true;
}

ViewportLayout::Layout ViewportLayout::Compute() const {
    Layout    L  = {};
    const int pw = PresentedWidth();
    const int ph = PresentedHeight();
    const int cw = canvas_w_;
    const int ch = canvas_h_;
    if (pw <= 0 || ph <= 0 || cw <= 0 || ch <= 0) return L;

    L.quarter            = presentation_.quarter & 3;
    L.surface_w          = static_cast<int>(SurfaceWidth());
    L.surface_h          = static_cast<int>(SurfaceHeight());
    const ContentBox box = presentation_.PresentedBox(SurfaceWidth(), SurfaceHeight());
    const double     bw  = pw * box.Width();
    const double     bh  = ph * box.Height();

    if (mode_ == ViewportMode::Stretch) {
        const double sx = cw / bw;
        const double sy = ch / bh;
        L.dst_x         = Round(-box.left * pw * sx);
        L.dst_y         = Round(-box.top * ph * sy);
        L.dst_w         = std::max(1, Round(pw * sx));
        L.dst_h         = std::max(1, Round(ph * sy));
        return L;
    }
    if (mode_ == ViewportMode::Aspect) {
        const double scale = std::min(cw / bw, ch / bh);
        L.dst_x            = Round((cw - bw * scale) / 2.0 - box.left * pw * scale);
        L.dst_y            = Round((ch - bh * scale) / 2.0 - box.top * ph * scale);
        L.dst_w            = std::max(1, Round(pw * scale));
        L.dst_h            = std::max(1, Round(ph * scale));
        return L;
    }
    if (mode_ == ViewportMode::Placed) {
        L.dst_x = Round(placed_x_);
        L.dst_y = Round(placed_y_);
        L.dst_w = std::max(1, Round(pw * placed_scale_));
        L.dst_h = std::max(1, Round(ph * placed_scale_));
        return L;
    }

    const int f         = ScaleFactor();
    const int content_w = ContentWidth();
    const int content_h = ContentHeight();
    const int origin_x  = content_w <= cw ? (cw - content_w) / 2 : -std::clamp(scroll_x_, 0, content_w - cw);
    const int origin_y  = content_h <= ch ? (ch - content_h) / 2 : -std::clamp(scroll_y_, 0, content_h - ch);
    L.dst_x             = origin_x + Round(-box.left * pw * f);
    L.dst_y             = origin_y + Round(-box.top * ph * f);
    L.dst_w             = pw * f;
    L.dst_h             = ph * f;
    return L;
}

void ViewportLayout::GuestPixelScale(double& sx, double& sy) const {
    const Layout L = Compute();
    sx             = L.dst_w > 0 ? static_cast<double>(L.dst_w) / PresentedWidth() : 0.0;
    sy             = L.dst_h > 0 ? static_cast<double>(L.dst_h) / PresentedHeight() : 0.0;
}

bool ViewportLayout::HostToGuest(int cx, int cy, int& sx, int& sy) const {
    const Layout L = Compute();
    if (L.dst_w <= 0 || L.dst_h <= 0) {
        sx = sy = 0;
        return false;
    }
    const FramePlacement place  = L.Placement();
    const FramePoint     device = place.ToDevice(FramePoint{cx + 0.5, cy + 0.5});
    const double         dw     = place.DeviceWidth();
    const double         dh     = place.DeviceHeight();
    sx = static_cast<int>(std::floor(device.x * SurfaceWidth() / dw));
    sy = static_cast<int>(std::floor(device.y * SurfaceHeight() / dh));
    return device.x >= 0.0 && device.x < dw && device.y >= 0.0 && device.y < dh;
}

void ViewportLayout::ClampGuest(int& sx, int& sy) const {
    const int sw = static_cast<int>(SurfaceWidth());
    const int sh = static_cast<int>(SurfaceHeight());
    sx           = std::clamp(sx, 0, sw > 0 ? sw - 1 : 0);
    sy           = std::clamp(sy, 0, sh > 0 ? sh - 1 : 0);
}

ViewportLayout::Scroll ViewportLayout::UpdateScroll() {
    Scroll s;
    s.content_w           = ContentWidth();
    s.content_h           = ContentHeight();
    s.page_w              = canvas_w_;
    s.page_h              = canvas_h_;
    const bool scrollable = active_ && FixedScale();
    s.horizontal          = scrollable && s.content_w > canvas_w_;
    s.vertical            = scrollable && s.content_h > canvas_h_;
    scroll_x_             = s.horizontal ? std::clamp(scroll_x_, 0, s.content_w - canvas_w_) : 0;
    scroll_y_             = s.vertical ? std::clamp(scroll_y_, 0, s.content_h - canvas_h_) : 0;
    s.pos_x               = scroll_x_;
    s.pos_y               = scroll_y_;
    return s;
}

void ViewportLayout::ScrollTo(bool horizontal, int pos) {
    if (horizontal) scroll_x_ = std::clamp(pos, 0, std::max(0, ContentWidth() - canvas_w_));
    else            scroll_y_ = std::clamp(pos, 0, std::max(0, ContentHeight() - canvas_h_));
}

}
