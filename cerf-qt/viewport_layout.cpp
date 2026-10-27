#include "viewport_layout.h"

#include <algorithm>
#include <cmath>

namespace cerffrontend {

void ViewportLayout::SetSurfaceSize(uint32_t w, uint32_t h) {
    surface_w_.store(w, std::memory_order_release);
    surface_h_.store(h, std::memory_order_release);
}

void ViewportLayout::SetCanvasSize(int w, int h) {
    canvas_w_ = w;
    canvas_h_ = h;
}

int ViewportLayout::ContentWidth() const {
    const int sw = static_cast<int>(SurfaceWidth());
    return mode_ == ViewportMode::Integer ? sw * integer_factor_ : sw;
}

int ViewportLayout::ContentHeight() const {
    const int sh = static_cast<int>(SurfaceHeight());
    return mode_ == ViewportMode::Integer ? sh * integer_factor_ : sh;
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

bool ViewportLayout::SetActive(bool active) {
    if (active_ == active) return false;
    active_ = active;
    return true;
}

ViewportLayout::Layout ViewportLayout::Compute() const {
    Layout    L  = {};
    const int sw = static_cast<int>(SurfaceWidth());
    const int sh = static_cast<int>(SurfaceHeight());
    const int cw = canvas_w_;
    const int ch = canvas_h_;
    if (sw <= 0 || sh <= 0 || cw <= 0 || ch <= 0) return L;

    if (mode_ == ViewportMode::Stretch) {
        L.stretch = true;
        L.dst_w   = cw;
        L.dst_h   = ch;
        L.src_w   = sw;
        L.src_h   = sh;
        return L;
    }
    if (mode_ == ViewportMode::Aspect) {
        const double scale = std::min(static_cast<double>(cw) / sw, static_cast<double>(ch) / sh);
        const int    fw    = std::max(1, static_cast<int>(sw * scale + 0.5));
        const int    fh    = std::max(1, static_cast<int>(sh * scale + 0.5));
        L.stretch = true;
        L.dst_x   = (cw - fw) / 2;
        L.dst_y   = (ch - fh) / 2;
        L.dst_w   = fw;
        L.dst_h   = fh;
        L.src_w   = sw;
        L.src_h   = sh;
        return L;
    }
    if (mode_ == ViewportMode::Placed) {
        L.stretch = true;
        L.src_w   = sw;
        L.src_h   = sh;
        L.dst_x   = static_cast<int>(std::lround(placed_x_));
        L.dst_y   = static_cast<int>(std::lround(placed_y_));
        L.dst_w   = std::max(1, static_cast<int>(std::lround(sw * placed_scale_)));
        L.dst_h   = std::max(1, static_cast<int>(std::lround(sh * placed_scale_)));
        return L;
    }
    if (mode_ == ViewportMode::Integer) {
        const int scaled_w = sw * integer_factor_;
        const int scaled_h = sh * integer_factor_;
        L.stretch = true;
        L.src_w   = sw;
        L.src_h   = sh;
        L.dst_w   = scaled_w;
        L.dst_h   = scaled_h;
        L.dst_x   = scaled_w <= cw ? (cw - scaled_w) / 2 : -std::clamp(scroll_x_, 0, scaled_w - cw);
        L.dst_y   = scaled_h <= ch ? (ch - scaled_h) / 2 : -std::clamp(scroll_y_, 0, scaled_h - ch);
        return L;
    }

    if (sw > cw) {
        L.src_x = std::clamp(scroll_x_, 0, sw - cw);
        L.src_w = cw;
        L.dst_w = cw;
    } else {
        L.src_w = sw;
        L.dst_x = (cw - sw) / 2;
        L.dst_w = sw;
    }
    if (sh > ch) {
        L.src_y = std::clamp(scroll_y_, 0, sh - ch);
        L.src_h = ch;
        L.dst_h = ch;
    } else {
        L.src_h = sh;
        L.dst_y = (ch - sh) / 2;
        L.dst_h = sh;
    }
    return L;
}

bool ViewportLayout::HostToGuest(int cx, int cy, int& sx, int& sy) const {
    const Layout L = Compute();
    if (L.dst_w <= 0 || L.dst_h <= 0) {
        sx = sy = 0;
        return false;
    }
    if (L.stretch) {
        sx = L.src_x + static_cast<int>(static_cast<long long>(cx - L.dst_x) * L.src_w / L.dst_w);
        sy = L.src_y + static_cast<int>(static_cast<long long>(cy - L.dst_y) * L.src_h / L.dst_h);
    } else {
        sx = L.src_x + (cx - L.dst_x);
        sy = L.src_y + (cy - L.dst_y);
    }
    return cx >= L.dst_x && cx < L.dst_x + L.dst_w && cy >= L.dst_y && cy < L.dst_y + L.dst_h;
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
    const bool scrollable = active_ && (mode_ == ViewportMode::Original || mode_ == ViewportMode::Integer);
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
