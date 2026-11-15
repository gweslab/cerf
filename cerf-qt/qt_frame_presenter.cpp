#include "qt_frame_presenter.h"

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

void QtFramePresenter::UiTick(cerfcore::CerfEmulator& emu) {
    hooks_->OnUiTick(emu);
    if (!capture_) return;
    ShadedFrame                frame;
    const ShaderCapture::State state = capture_->Take(frame);
    if (state == ShaderCapture::State::kPending) return;
    capture_.reset();
    hooks_->ShadedCaptured(emu, state == ShaderCapture::State::kCaptured ? &frame : nullptr);
}

void QtFramePresenter::RequestShadedCapture() {
    if (!capture_) capture_ = std::make_shared<ShaderCapture>();
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

void QtFramePresenter::SetCanvasSize(int w, int h) { layout_.SetCanvasSize(w, h); }

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

const FrameLayers& QtFramePresenter::Present(cerfcore::CerfEmulator& emu, cerfcore::FrameSource& source) {
    hooks_->OnPresentTick(emu);
    if (shader_result_.generation != reported_shader_.generation ||
        shader_result_.applied != reported_shader_.applied) {
        reported_shader_ = shader_result_;
        hooks_->ShadersApplied(emu, shader_result_);
    }
    layers_               = FrameLayers{};
    layers_.shaders       = CopyShaders(hooks_->Shaders(emu));
    layers_.shader_result = &shader_result_;
    layers_.capture       = capture_;
    layers_.canvas_w      = layout_.CanvasWidth();
    layers_.canvas_h = layout_.CanvasHeight();
    if (layers_.canvas_w <= 0 || layers_.canvas_h <= 0) return layers_;
    layers_.background = background_;
    layers_.frozen     = hooks_->FreezeFrame(emu);
    if (hooks_->ShowsGuest(emu)) PresentGuest(emu, source);
    return layers_;
}

const ShaderChainSpec* QtFramePresenter::CopyShaders(const ShaderChainSpec* spec) {
    if (spec == nullptr) return nullptr;
    if (spec->generation != shaders_.generation || spec->parameter_generation != shaders_.parameter_generation)
        shaders_ = *spec;
    return &shaders_;
}

void QtFramePresenter::PresentGuest(cerfcore::CerfEmulator& emu, cerfcore::FrameSource& source) {
    if (!source.HasFrame() || guest_.isNull()) return;
    auto*     guest_bits = reinterpret_cast<uint32_t*>(guest_.bits());
    const int count      = static_cast<int>(layout_.SurfaceWidth() * layout_.SurfaceHeight());
    source.RenderInto(guest_bits, layout_.SurfaceWidth(), layout_.SurfaceHeight());
    ForceOpaque(guest_bits, static_cast<size_t>(count));

    const cerffrontend::ViewportLayout::Layout L = layout_.Compute();
    if (L.dst_w <= 0 || L.dst_h <= 0) return;
    QTransform turn;
    switch (L.quarter) {
        case 1:  turn.translate(L.dst_x + L.dst_w, L.dst_y); break;
        case 2:  turn.translate(L.dst_x + L.dst_w, L.dst_y + L.dst_h); break;
        case 3:  turn.translate(L.dst_x, L.dst_y + L.dst_h); break;
        default: turn.translate(L.dst_x, L.dst_y); break;
    }
    turn.rotate(90.0 * L.quarter);
    const bool turned     = (L.quarter & 1) != 0;
    layers_.guest         = &guest_;
    layers_.turn          = turn;
    layers_.target_w      = turned ? L.dst_h : L.dst_w;
    layers_.target_h      = turned ? L.dst_w : L.dst_h;
    const int    margin   = std::max({L.dst_x, L.dst_y, layers_.canvas_w - L.dst_x - L.dst_w,
                                       layers_.canvas_h - L.dst_y - L.dst_h});
    const double strength = glow_.Strength(layout_.FitZoom(), layout_.CoverZoom());
    const bool   glowing  = margin > 0 && strength > 0.0;
    const int    reach    = glowing ? static_cast<int>(std::lround(hooks_->GlowReach(emu, L))) : 0;
    if (!glow_.Update(guest_, layers_.target_w, layers_.target_h, reach, strength, layers_.background)) return;
    layers_.glow            = &glow_.Image();
    layers_.glow_rect       = glow_.Rect(layers_.target_w, layers_.target_h);
    layers_.glow_generation = glow_.Generation();
}

void QtFramePresenter::ForceOpaque(uint32_t* pixels, size_t count) {
    for (size_t i = 0; i < count; ++i) pixels[i] |= 0xFF000000u;
}
