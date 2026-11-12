#include "qt_frame_presenter.h"

#include "present_effects.h"

#include <QPainter>

#include <algorithm>
#include <cmath>

QtFramePresenter::QtFramePresenter(std::unique_ptr<QtPresentHooks> hooks, uint32_t surf_w, uint32_t surf_h,
                                   QColor background)
    : hooks_(std::move(hooks)), background_(background) {
    SetGuestSurfaceSize(surf_w, surf_h);
    repaint_timer_.setTimerType(Qt::PreciseTimer);
}

void QtFramePresenter::StartRepaints(int interval_ms, std::function<void()> repaint) {
    QObject::connect(&repaint_timer_, &QTimer::timeout, std::move(repaint));
    repaint_timer_.start(interval_ms);
}

void QtFramePresenter::UiTick(cerfcore::CerfEmulator& emu) { hooks_->OnUiTick(emu); }

void QtFramePresenter::DrawTo(cerfcore::CerfEmulator& emu, cerfcore::FrameSource& source, QPainter& painter,
                              int visible_w, int visible_h, qreal dpr) {
    const QImage& image = Present(emu, source, visible_w, visible_h, dpr);
    painter.drawImage(QRectF(0, 0, image.width() / dpr, image.height() / dpr), image);
}

bool QtFramePresenter::SetGuestSurfaceSize(uint32_t w, uint32_t h) {
    if (w == 0) w = 1;
    if (h == 0) h = 1;
    if (w == layout_.SurfaceWidth() && h == layout_.SurfaceHeight() && !guest_.isNull()) return false;
    guest_ = QImage(static_cast<int>(w), static_cast<int>(h), QImage::Format_RGB32);
    guest_.fill(background_);
    layout_.SetSurfaceSize(w, h);
    layout_.ResetScroll();
    return true;
}

void QtFramePresenter::SetCanvasSize(int w, int h) {
    if (present_.width() != w || present_.height() != h) {
        present_ = QImage(w, h, QImage::Format_RGB32);
        present_.fill(background_);
    }
    layout_.SetCanvasSize(w, h);
}

bool QtFramePresenter::Capture(cerfcore::FrameSource& source, std::vector<uint32_t>& out, uint32_t& w,
                               uint32_t& h) {
    if (!source.HasFrame()) return false;
    const uint32_t sw = layout_.SurfaceWidth();
    const uint32_t sh = layout_.SurfaceHeight();
    if (sw == 0 || sh == 0 || guest_.isNull()) return false;
    auto* bits = reinterpret_cast<uint32_t*>(guest_.bits());
    source.RenderInto(bits, sw, sh);
    out.assign(bits, bits + static_cast<size_t>(sw) * sh);
    w = sw;
    h = sh;
    return true;
}

bool QtFramePresenter::ComposeInto(cerfcore::CerfEmulator& emu, cerfcore::FrameSource& source) {
    if (!source.HasFrame() || guest_.isNull()) {
        present_.fill(background_);
        return false;
    }
    auto* guest_bits = reinterpret_cast<uint32_t*>(guest_.bits());
    source.RenderInto(guest_bits, layout_.SurfaceWidth(), layout_.SurfaceHeight());
    ForceOpaque(guest_bits, static_cast<size_t>(layout_.SurfaceWidth()) * layout_.SurfaceHeight());

    const cerffrontend::ViewportLayout::Layout L = layout_.Compute();
    if (L.dst_w <= 0 || L.dst_h <= 0) {
        present_.fill(background_);
        return true;
    }
    QTransform turn;
    switch (L.quarter) {
        case 1:  turn.translate(L.dst_x + L.dst_w, L.dst_y); break;
        case 2:  turn.translate(L.dst_x + L.dst_w, L.dst_y + L.dst_h); break;
        case 3:  turn.translate(L.dst_x, L.dst_y + L.dst_h); break;
        default: turn.translate(L.dst_x, L.dst_y); break;
    }
    turn.rotate(90.0 * L.quarter);
    const bool turned   = (L.quarter & 1) != 0;
    const int  target_w = turned ? L.dst_h : L.dst_w;
    const int  target_h = turned ? L.dst_w : L.dst_h;
    const int  margin   = std::max({L.dst_x, L.dst_y, present_.width() - L.dst_x - L.dst_w,
                                    present_.height() - L.dst_y - L.dst_h});
    const double strength = glow_.Strength(layout_.FitZoom(), layout_.CoverZoom());
    const bool   glowing  = margin > 0 && strength > 0.0;
    const int    reach    = glowing ? static_cast<int>(std::lround(hooks_->GlowReach(emu, L))) : 0;
    glow_.Compose(present_, guest_, turn, target_w, target_h, reach, strength, background_);
    QPainter p(&present_);
    p.setRenderHint(QPainter::SmoothPixmapTransform, layout_.Antialias());
    p.setTransform(turn);
    p.drawImage(QRect(0, 0, target_w, target_h), guest_);
    return true;
}

const QImage& QtFramePresenter::Present(cerfcore::CerfEmulator& emu, cerfcore::FrameSource& source,
                                        int visible_w, int visible_h, qreal dpr) {
    hooks_->OnPresentTick(emu, source.HasFrame());
    if (present_.isNull()) return present_;
    auto*     bits = reinterpret_cast<uint32_t*>(present_.bits());
    const int w    = present_.width();
    const int h    = present_.height();
    if (hooks_->RenderAlt(emu, bits, w, h, dpr)) {
        ForceOpaque(bits, static_cast<size_t>(w) * h);
    } else {
        ComposeInto(emu, source);
        hooks_->RenderFrameOverlay(emu, present_, layout_.Compute(), dpr);
    }
    if (hooks_->ShouldDesaturate(emu)) cerffrontend::PresentEffects::DesaturateAndDim(bits, w * h);
    hooks_->RenderOverlay(emu, present_, std::min(w, visible_w), std::min(h, visible_h), dpr);
    return present_;
}

void QtFramePresenter::ForceOpaque(uint32_t* pixels, size_t count) {
    for (size_t i = 0; i < count; ++i) pixels[i] |= 0xFF000000u;
}
