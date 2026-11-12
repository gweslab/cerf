#include "surface_scroll.h"

#include <cmath>

void SurfaceScroll::Bind(cerffrontend::ViewportLayout* layout) {
    layout_ = layout;
    scroll_ = {};
    if (layout_) Refresh();
    else         emit changed();
}

void SurfaceScroll::Refresh() {
    const cerffrontend::ViewportLayout::Scroll s = layout_->UpdateScroll();
    if (s.horizontal == scroll_.horizontal && s.vertical == scroll_.vertical && s.content_w == scroll_.content_w &&
        s.content_h == scroll_.content_h && s.page_w == scroll_.page_w && s.page_h == scroll_.page_h &&
        s.pos_x == scroll_.pos_x && s.pos_y == scroll_.pos_y)
        return;
    scroll_ = s;
    emit changed();
}

qreal SurfaceScroll::Fraction(int part, int whole) { return whole > 0 ? qreal(part) / whole : 0.0; }

qreal SurfaceScroll::HorizontalSize() const { return Fraction(scroll_.page_w, scroll_.content_w); }

qreal SurfaceScroll::VerticalSize() const { return Fraction(scroll_.page_h, scroll_.content_h); }

qreal SurfaceScroll::HorizontalPosition() const { return Fraction(scroll_.pos_x, scroll_.content_w); }

qreal SurfaceScroll::VerticalPosition() const { return Fraction(scroll_.pos_y, scroll_.content_h); }

void SurfaceScroll::ScrollTo(bool horizontal, qreal position) {
    const int whole = horizontal ? scroll_.content_w : scroll_.content_h;
    layout_->ScrollTo(horizontal, static_cast<int>(std::lround(position * whole)));
    Refresh();
    emit scrolled();
}
