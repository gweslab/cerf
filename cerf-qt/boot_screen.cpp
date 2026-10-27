#include "boot_screen.h"

#include "boot_bar.h"
#include "dpi_scale.h"
#include "surface_factory.h"

#include <cerfcore/boards/board_context.h>
#include <cerfcore/core/cerf_emulator.h>
#include <cerfcore/host/emulation_pause.h>
#include <cerfcore/host/guest_power_notifier.h>
#include <cerfcore/host/hw_screen.h>

#include <algorithm>
#include <cmath>
#include <cstring>

namespace cerffrontend {

REGISTER_SERVICE(BootScreen);

namespace {

constexpr uint64_t kCerfFadeInMs = 350;
constexpr uint64_t kCerfHoldMs   = 1200;
constexpr uint64_t kTextFadeInMs = 350;
constexpr uint64_t kTextHoldMs   = 2000;

constexpr float kDimOpacity = 0.15f;

constexpr uint32_t kCerfLogoMinPx = 96;
constexpr uint32_t kCerfLogoMaxPx = 220;
constexpr int      kWatermarkPx   = 1024;

constexpr float kLabelGapFrac = 0.14f;

constexpr float    kGlowRadiusScale = 1.9f;
constexpr uint32_t kGlowCenterR     = 0x19;
constexpr uint32_t kGlowCenterG     = 0x20;
constexpr uint32_t kGlowCenterB     = 0x28;

constexpr int kLabelFontPx    = 18;
constexpr int kHwLineFontPx   = 12;
constexpr int kMargin         = 8;
constexpr int kHwLineHeightPx = kHwLineFontPx + 4;
constexpr int kLabelBottomPx  = 8;
constexpr int kHwLineGapPx    = 4;
constexpr int kHwHitSlackPx   = 2;

}

int BootScreen::S(int px) const { return ScaleForDpi(px, dpi_); }

void BootScreen::OnReady() {
    short_name_ = emu_.Get<cerfcore::BoardContext>().ShortBoardName();
    emu_.Get<cerfcore::GuestPowerNotifier>().RegisterRebootListener([this] { Restart(); });
}

void BootScreen::RenderInto(uint32_t* dib_bgra32, uint32_t width, uint32_t height, int dpi) {
    Advance(emu_.Get<cerfcore::EmulationPause>().AnimationTickMs());

    if (!bg_ || bg_->Width() != static_cast<int>(width) || bg_->Height() != static_cast<int>(height)) {
        bg_       = emu_.Get<SurfaceFactory>().Create(static_cast<int>(width), static_cast<int>(height));
        bg_valid_ = false;
    }
    if (dpi != dpi_) {
        dpi_      = dpi;
        bg_valid_ = false;
    }

    const uint64_t sig = BgSignature(width, height);
    if (!bg_valid_ || sig != bg_sig_) {
        uint32_t* bits = bg_->Bits();
        std::memset(bits, 0, static_cast<size_t>(width) * height * 4u);
        Painter&    p    = bg_->Paint();
        label_line_h_    = p.Metrics(LabelFont()).line_height;
        const float glow = GlowOpacity();
        DrawGlow(bits, width, height, LogoRect(width, height, glow, false), glow);
        if (!Finished()) DrawAnimation(p, width, height);
        else             DrawLogoFrame(p, width, height, 1.0f, true, CurrentLabelText(), 1.0f);
        DrawHwStatusLine(p, width, height);
        bg_->Flush();
        bg_sig_   = sig;
        bg_valid_ = true;
    }

    std::memcpy(dib_bgra32, bg_->Bits(), static_cast<size_t>(width) * height * 4u);
    emu_.Get<BootBar>().RenderInto(dib_bgra32, width, height, dpi_);
}

uint64_t BootScreen::BgSignature(uint32_t width, uint32_t height) {
    uint64_t s   = 1469598103934665603ull;
    auto     mix = [&](uint64_t v) { s = (s ^ v) * 1099511628211ull; };
    mix(static_cast<uint64_t>(phase_));
    mix(static_cast<uint64_t>(static_cast<int>(cur_op_ * 256.0f)));
    mix(static_cast<uint64_t>(label_mode_));
    mix(fb_latched_ ? 1u : 0u);
    mix(width);
    mix(height);
    hw_line_ = emu_.Get<cerfcore::HwScreen>().LastLine();
    for (unsigned char c : hw_line_) mix(c);
    mix(hw_line_.size());
    return s;
}

Font BootScreen::LabelFont() const { return Font{FontFace::kUi, S(kLabelFontPx), true}; }

int BootScreen::HwLineTop(uint32_t height) const {
    return static_cast<int>(height) - BootBar::Height(dpi_) - S(kHwLineGapPx) - S(kHwLineHeightPx);
}

int BootScreen::ContentBottom(uint32_t height) const {
    if (hw_line_.empty()) return static_cast<int>(height) - BootBar::Height(dpi_) - S(kLabelBottomPx);
    return HwLineTop(height) - S(kHwLineGapPx);
}

std::string BootScreen::CurrentLabelText() const {
    if (fb_latched_) return "LCD is rendering.";
    if (label_mode_ == LabelMode::Restarting) {
        const char* over = restart_label_.load(std::memory_order_acquire);
        return over ? over : "Rebooting...";
    }
    return "Booting " + short_name_ + "...";
}

Rect BootScreen::LogoRect(uint32_t width, uint32_t height, float label_progress, bool native) const {
    int dst_w = 0, dst_h = 0;
    if (native) {
        dst_w = dst_h = kWatermarkPx;
    } else {
        const uint32_t md = std::min(width, height);
        const int      wanted = static_cast<int>(std::clamp(
            md / 3u, static_cast<uint32_t>(S(static_cast<int>(kCerfLogoMinPx))),
            static_cast<uint32_t>(S(static_cast<int>(kCerfLogoMaxPx)))));
        const float fit = (static_cast<float>(ContentBottom(height)) - static_cast<float>(height) * 0.5f +
                           static_cast<float>(S(kLabelFontPx)) * 0.5f - static_cast<float>(label_line_h_)) /
                          (0.5f + kLabelGapFrac * 0.5f);
        dst_w = dst_h = std::clamp(static_cast<int>(fit), 0, wanted);
    }

    label_progress   = std::clamp(label_progress, 0.0f, 1.0f);
    const float gap  = static_cast<float>(dst_h) * kLabelGapFrac;
    const float rise = (gap + static_cast<float>(S(kLabelFontPx))) * 0.5f * label_progress;

    const int left = static_cast<int>(width) / 2 - dst_w / 2;
    const int top  = static_cast<int>(static_cast<float>(height) * 0.5f - rise) - dst_h / 2;
    return Rect{left, top, left + dst_w, top + dst_h};
}

float BootScreen::GlowOpacity() const {
    switch (phase_) {
        case Phase::CerfFadeIn:
        case Phase::CerfHold:   return 0.0f;
        case Phase::TextFadeIn: return cur_op_;
        case Phase::TextHold:
        case Phase::Finished:   return 1.0f;
    }
    return 0.0f;
}

void BootScreen::DrawGlow(uint32_t* bits, uint32_t width, uint32_t height, const Rect& logo,
                          float opacity) const {
    opacity = std::clamp(opacity, 0.0f, 1.0f);
    if (!bits || opacity <= 0.0f) return;

    const float cx     = static_cast<float>(logo.left + logo.right) * 0.5f;
    const float cy     = static_cast<float>(logo.top + logo.bottom) * 0.5f;
    const float radius = static_cast<float>(std::max(logo.Width(), logo.Height())) * kGlowRadiusScale;
    if (radius <= 1.0f) return;

    const int x0 = std::max(0, static_cast<int>(cx - radius));
    const int x1 = std::min(static_cast<int>(width), static_cast<int>(cx + radius) + 1);
    const int y0 = std::max(0, static_cast<int>(cy - radius));
    const int y1 = std::min(static_cast<int>(height), static_cast<int>(cy + radius) + 1);

    const float inv_r = 1.0f / radius;
    for (int y = y0; y < y1; ++y) {
        const float dy  = static_cast<float>(y) + 0.5f - cy;
        uint32_t*   row = bits + static_cast<size_t>(y) * width;
        for (int x = x0; x < x1; ++x) {
            const float dx = static_cast<float>(x) + 0.5f - cx;
            const float d  = std::sqrt(dx * dx + dy * dy) * inv_r;
            if (d >= 1.0f) continue;
            const float    t = 1.0f - d;
            const float    a = t * t * (3.0f - 2.0f * t) * opacity;
            const uint32_t r = static_cast<uint32_t>(static_cast<float>(kGlowCenterR) * a + 0.5f);
            const uint32_t g = static_cast<uint32_t>(static_cast<float>(kGlowCenterG) * a + 0.5f);
            const uint32_t b = static_cast<uint32_t>(static_cast<float>(kGlowCenterB) * a + 0.5f);
            row[x] = (r << 16) | (g << 8) | b;
        }
    }
}

void BootScreen::Advance(uint64_t now) {
    if (!started_) {
        started_     = true;
        phase_       = Phase::CerfFadeIn;
        phase_start_ = now;
    }
    if (restart_req_.exchange(false)) {
        label_mode_ = LabelMode::Restarting;
        fb_latched_ = false;
        fb_latched_req_.store(false, std::memory_order_release);
        phase_       = Phase::TextFadeIn;
        phase_start_ = now;
    }
    if (fb_latched_req_.exchange(false)) {
        fb_latched_ = true;
        phase_      = Phase::Finished;
    }

    const uint64_t elapsed = now >= phase_start_ ? now - phase_start_ : 0;
    switch (phase_) {
        case Phase::CerfFadeIn:
            cur_op_ = std::min(1.0f, static_cast<float>(elapsed) / static_cast<float>(kCerfFadeInMs));
            if (elapsed >= kCerfFadeInMs) {
                phase_       = Phase::CerfHold;
                phase_start_ = now;
            }
            break;
        case Phase::CerfHold:
            cur_op_ = 1.0f;
            if (elapsed >= kCerfHoldMs) {
                phase_       = Phase::TextFadeIn;
                phase_start_ = now;
                cur_op_      = 0.0f;
            }
            break;
        case Phase::TextFadeIn:
            cur_op_ = std::min(1.0f, static_cast<float>(elapsed) / static_cast<float>(kTextFadeInMs));
            if (elapsed >= kTextFadeInMs) {
                phase_       = Phase::TextHold;
                phase_start_ = now;
            }
            break;
        case Phase::TextHold:
            cur_op_ = 1.0f;
            if (elapsed >= kTextHoldMs) phase_ = Phase::Finished;
            break;
        case Phase::Finished:
            cur_op_ = 1.0f;
            break;
    }
}

void BootScreen::DrawLogoFrame(Painter& p, uint32_t width, uint32_t height, float logo_opacity,
                               bool show_label, const std::string& label, float text_opacity,
                               bool native_size) {
    logo_opacity = std::clamp(logo_opacity, 0.0f, 1.0f);
    text_opacity = std::clamp(text_opacity, 0.0f, 1.0f);

    const Rect lr = LogoRect(width, height, show_label ? text_opacity : 0.0f, native_size);
    if (lr.Width() > 0 && lr.Height() > 0) p.DrawImage(lr, PainterImage::kCerfLogo, logo_opacity);

    if (!show_label || text_opacity <= 0.0f) return;

    const uint8_t v       = static_cast<uint8_t>(255.0f * text_opacity);
    const int     max_y   = ContentBottom(height) - label_line_h_;
    const int     label_y = std::min(lr.bottom + static_cast<int>(static_cast<float>(lr.Height()) * kLabelGapFrac),
                                     max_y);
    p.DrawTextBox({0, label_y, static_cast<int>(width), label_y + label_line_h_}, label, LabelFont(), Rgb{v, v, v},
                  text::kCenter | text::kTop | text::kSingleLine);
}

void BootScreen::DrawAnimation(Painter& p, uint32_t width, uint32_t height) {
    switch (phase_) {
        case Phase::CerfFadeIn:
        case Phase::CerfHold:
            DrawLogoFrame(p, width, height, cur_op_, false, std::string(), 0.0f);
            break;
        case Phase::TextFadeIn:
        case Phase::TextHold:
            DrawLogoFrame(p, width, height, 1.0f, true, CurrentLabelText(), cur_op_);
            break;
        case Phase::Finished:
            break;
    }
}

void BootScreen::DrawHwStatusLine(Painter& p, uint32_t width, uint32_t height) {
    hw_line_rect_ = Rect{};
    if (hw_line_.empty()) return;

    const float   op    = phase_ == Phase::CerfFadeIn ? cur_op_ : 1.0f;
    const uint8_t dv    = static_cast<uint8_t>(150.0f * op);
    const int     bar_h = BootBar::Height(dpi_);
    const int     top   = HwLineTop(height);
    const Rect r{S(kMargin), top, static_cast<int>(width) - S(kMargin), top + S(kHwLineHeightPx)};
    p.DrawTextBox(r, hw_line_, Font{FontFace::kMono, S(kHwLineFontPx), true}, Rgb{dv, dv, dv},
                  text::kCenter | text::kVCenter | text::kSingleLine | text::kEndEllipsis);
    hw_line_rect_ = Rect{0, r.top - S(kHwHitSlackPx), static_cast<int>(width),
                         static_cast<int>(height) - bar_h};
}

bool BootScreen::HitTestHwLine(int x, int y) const {
    return hw_line_rect_.Contains(x, y);
}

void BootScreen::DrawWatermark(Painter& p, uint32_t width, uint32_t height) {
    DrawLogoFrame(p, width, height, kDimOpacity, false, std::string(), 0.0f, true);
}

void BootScreen::Restart() {
    restart_req_.store(true, std::memory_order_release);
}

void BootScreen::SetRestartLabel(const char* static_text) {
    restart_label_.store(static_text, std::memory_order_release);
}

void BootScreen::OnFramebufferLatched() {
    restart_label_.store(nullptr, std::memory_order_release);
    fb_latched_req_.store(true);
}

}
