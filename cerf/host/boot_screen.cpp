#define NOMINMAX

#include "boot_screen.h"

#include "../boards/board_context.h"
#include "../core/cerf_emulator.h"
#include "../core/string_utils.h"
#include "boot_bar.h"
#include "emulation_pause.h"
#include "host_fonts.h"
#include "host_gdiplus.h"
#include "hw_screen.h"

#include <algorithm>
#include <cmath>
#include <cstring>
#include <objbase.h>
#include <gdiplus.h>

REGISTER_SERVICE(BootScreen);

namespace {

constexpr uint64_t kCerfFadeInMs  = 350;
constexpr uint64_t kCerfHoldMs    = 1200;
constexpr uint64_t kTextFadeInMs  = 350;
constexpr uint64_t kTextHoldMs    = 2000;

constexpr float    kDimOpacity    = 0.15f;

constexpr uint32_t kCerfLogoMinPx = 96;
constexpr uint32_t kCerfLogoMaxPx = 220;

constexpr float    kLabelGapFrac    = 0.14f;

constexpr float    kGlowRadiusScale = 1.9f;
constexpr uint32_t kGlowCenterR     = 0x19;
constexpr uint32_t kGlowCenterG     = 0x20;
constexpr uint32_t kGlowCenterB     = 0x28;

constexpr int      kLabelFontPx      = 18;
constexpr int      kHwLineFontPx = 12;
constexpr int      kMargin           = 8;
constexpr int      kBootBarPx        = 16;
constexpr int      kHwLineHeightPx   = kHwLineFontPx + 4;

}  /* namespace */

BootScreen::~BootScreen() {
    if (label_font_)      DeleteObject(label_font_);
    if (hw_line_font_) DeleteObject(hw_line_font_);
    if (bg_dc_)           DeleteDC(bg_dc_);
    if (bg_dib_)          DeleteObject(bg_dib_);
}

void BootScreen::OnShutdown() {
    /* Free GDI+ bitmaps here, not in ~BootScreen: OnShutdown runs before any
       destructor, so HostGdiPlus (GdiplusShutdown in its dtor) is still up.
       Deleting a Bitmap after GdiplusShutdown faults. */
    delete cerf_logo_; cerf_logo_ = nullptr;
}

void BootScreen::OnReady() {
    auto& bc = emu_.Get<BoardContext>();
    short_name_ = Utf8ToWide(BoardContext::ShortBoardName(bc.GetBoard()));
}

void BootScreen::RenderInto(HDC, uint32_t* dib_bgra32,
                            uint32_t width, uint32_t height) {
    Advance(emu_.Get<EmulationPause>().AnimationTickMs());

    if ((int)width != bg_w_ || (int)height != bg_h_) RebuildBgDib((int)width, (int)height);

    const uint64_t sig = BgSignature(width, height);
    if (bg_bits_ && (!bg_valid_ || sig != bg_sig_)) {
        std::memset(bg_bits_, 0, (size_t)bg_w_ * bg_h_ * 4u);
        const float glow = GlowOpacity();
        DrawGlow(bg_bits_, width, height,
                 LogoRect(width, height, glow, false), glow);
        if (!Finished()) DrawAnimation(bg_dc_, width, height);
        else             DrawHeldFinal(bg_dc_, width, height);
        DrawHwStatusLine(bg_dc_, width, height);
        GdiFlush();
        bg_sig_   = sig;
        bg_valid_ = true;
    }

    if (bg_bits_) std::memcpy(dib_bgra32, bg_bits_, (size_t)width * height * 4u);
    else          std::memset(dib_bgra32, 0, (size_t)width * height * 4u);
    emu_.Get<BootBar>().RenderInto(dib_bgra32, width, height);
}

void BootScreen::RebuildBgDib(int w, int h) {
    if (w < 1) w = 1;
    if (h < 1) h = 1;

    BITMAPINFO bmi = {};
    bmi.bmiHeader.biSize        = sizeof(bmi.bmiHeader);
    bmi.bmiHeader.biWidth       = w;
    bmi.bmiHeader.biHeight      = -h;
    bmi.bmiHeader.biPlanes      = 1;
    bmi.bmiHeader.biBitCount    = 32;
    bmi.bmiHeader.biCompression = BI_RGB;

    void* bits = nullptr;
    HBITMAP nd = CreateDIBSection(nullptr, &bmi, DIB_RGB_COLORS, &bits, nullptr, 0);
    if (!nd || !bits) { if (nd) DeleteObject(nd); return; }
    if (!bg_dc_) bg_dc_ = CreateCompatibleDC(nullptr);
    SelectObject(bg_dc_, nd);
    if (bg_dib_) DeleteObject(bg_dib_);
    bg_dib_   = nd;
    bg_bits_  = static_cast<uint32_t*>(bits);
    bg_w_     = w;
    bg_h_     = h;
    bg_valid_ = false;
}

uint64_t BootScreen::BgSignature(uint32_t width, uint32_t height) {
    uint64_t s = 1469598103934665603ull;
    auto mix = [&](uint64_t v) { s = (s ^ v) * 1099511628211ull; };
    mix((uint64_t)phase_);
    mix((uint64_t)(int)(cur_op_ * 256.0f));
    mix((uint64_t)label_mode_);
    mix(fb_latched_ ? 1u : 0u);
    mix(width);
    mix(height);
    const std::string last = emu_.Get<HwScreen>().LastLine();
    for (unsigned char c : last) mix(c);
    mix(last.size());
    return s;
}

void BootScreen::EnsureLogosLoaded() {
    if (logos_loaded_) return;
    logos_loaded_ = true;
    cerf_logo_ = emu_.Get<HostGdiPlus>().DecodeResourcePng(L"CERF_LOGO");
}

void BootScreen::EnsureFonts() {
    HostFonts& fonts = emu_.Get<HostFonts>();
    if (!label_font_)
        label_font_ = CreateFontW(-kLabelFontPx, 0, 0, 0, FW_BOLD, FALSE, FALSE,
                                  FALSE, DEFAULT_CHARSET, OUT_DEFAULT_PRECIS,
                                  CLIP_DEFAULT_PRECIS, CLEARTYPE_QUALITY,
                                  VARIABLE_PITCH | FF_SWISS, fonts.UiFace());
    if (!hw_line_font_)
        hw_line_font_ = CreateFontW(-kHwLineFontPx, 0, 0, 0, FW_BOLD, FALSE,
                                    FALSE, FALSE, DEFAULT_CHARSET, OUT_DEFAULT_PRECIS,
                                    CLIP_DEFAULT_PRECIS, CLEARTYPE_QUALITY,
                                    FIXED_PITCH | FF_MODERN, fonts.MonoFace());
}

std::wstring BootScreen::CurrentLabelText() const {
    if (fb_latched_) return L"LCD is rendering.";
    if (label_mode_ == LabelMode::Restarting) {
        const wchar_t* over = restart_label_.load(std::memory_order_acquire);
        return over ? over : L"Rebooting...";
    }
    return L"Booting " + short_name_ + L"...";
}

RECT BootScreen::LogoRect(uint32_t width, uint32_t height,
                          float label_progress, bool native) const {
    int dst_w = 0, dst_h = 0;
    if (native) {
        if (!cerf_logo_) return RECT{};
        dst_w = (int)cerf_logo_->GetWidth();
        dst_h = (int)cerf_logo_->GetHeight();
    } else {
        const uint32_t md = std::min(width, height);
        dst_w = dst_h = (int)std::clamp(md / 3u, kCerfLogoMinPx, kCerfLogoMaxPx);
    }

    label_progress = std::clamp(label_progress, 0.0f, 1.0f);
    const float gap  = (float)dst_h * kLabelGapFrac;
    const float rise = (gap + (float)kLabelFontPx) * 0.5f * label_progress;

    const int left = (int)width / 2 - dst_w / 2;
    const int top  = (int)((float)height * 0.5f - rise) - dst_h / 2;
    return RECT{ left, top, left + dst_w, top + dst_h };
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

void BootScreen::DrawGlow(uint32_t* bits, uint32_t width, uint32_t height,
                          const RECT& logo, float opacity) const {
    opacity = std::clamp(opacity, 0.0f, 1.0f);
    if (!bits || opacity <= 0.0f) return;

    const float cx = (float)(logo.left + logo.right) * 0.5f;
    const float cy = (float)(logo.top + logo.bottom) * 0.5f;
    const float radius = (float)std::max(logo.right - logo.left,
                                         logo.bottom - logo.top) * kGlowRadiusScale;
    if (radius <= 1.0f) return;

    const int x0 = std::max(0, (int)(cx - radius));
    const int x1 = std::min((int)width,  (int)(cx + radius) + 1);
    const int y0 = std::max(0, (int)(cy - radius));
    const int y1 = std::min((int)height, (int)(cy + radius) + 1);

    const float inv_r = 1.0f / radius;
    for (int y = y0; y < y1; ++y) {
        const float dy = (float)y + 0.5f - cy;
        uint32_t* row = bits + (size_t)y * width;
        for (int x = x0; x < x1; ++x) {
            const float dx = (float)x + 0.5f - cx;
            const float d  = std::sqrt(dx * dx + dy * dy) * inv_r;
            if (d >= 1.0f) continue;

            const float t = 1.0f - d;
            const float a = t * t * (3.0f - 2.0f * t) * opacity;
            const uint32_t r = (uint32_t)((float)kGlowCenterR * a + 0.5f);
            const uint32_t g = (uint32_t)((float)kGlowCenterG * a + 0.5f);
            const uint32_t b = (uint32_t)((float)kGlowCenterB * a + 0.5f);
            row[x] = (r << 16) | (g << 8) | b;
        }
    }
}

void BootScreen::Advance(uint64_t now) {
    if (!started_) { started_ = true; phase_ = Phase::CerfFadeIn; phase_start_ = now; }

    if (restart_req_.exchange(false)) {
        label_mode_  = LabelMode::Restarting;
        fb_latched_  = false;
        /* Drop a latch request the previous session left pending (Advance stops
           once the framebuffer tab takes over, so it was never consumed); else
           it fires this same Advance and flips the fresh label to "Switched to
           LCD". The resumed guest's first frame re-latches later. */
        fb_latched_req_.store(false, std::memory_order_release);
        phase_       = Phase::TextFadeIn;
        phase_start_ = now;
    }
    if (fb_latched_req_.exchange(false)) { fb_latched_ = true; phase_ = Phase::Finished; }

    const uint64_t elapsed = (now >= phase_start_) ? (now - phase_start_) : 0;

    switch (phase_) {
        case Phase::CerfFadeIn:
            cur_op_ = std::min(1.0f, (float)elapsed / (float)kCerfFadeInMs);
            if (elapsed >= kCerfFadeInMs) { phase_ = Phase::CerfHold; phase_start_ = now; }
            break;
        case Phase::CerfHold:
            cur_op_ = 1.0f;
            if (elapsed >= kCerfHoldMs) {
                phase_ = Phase::TextFadeIn; phase_start_ = now; cur_op_ = 0.0f;
            }
            break;
        case Phase::TextFadeIn:
            cur_op_ = std::min(1.0f, (float)elapsed / (float)kTextFadeInMs);
            if (elapsed >= kTextFadeInMs) { phase_ = Phase::TextHold; phase_start_ = now; }
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

void BootScreen::DrawLogoFrame(HDC dc, uint32_t width, uint32_t height,
                               float logo_opacity,
                               bool show_label, const std::wstring& label, float text_opacity,
                               bool cerf_native_size) {
    EnsureLogosLoaded();
    logo_opacity = std::clamp(logo_opacity, 0.0f, 1.0f);
    text_opacity = std::clamp(text_opacity, 0.0f, 1.0f);

    Gdiplus::Bitmap* bmp = cerf_logo_;

    const RECT lr = LogoRect(width, height,
                             show_label ? text_opacity : 0.0f, cerf_native_size);
    const int dst_w = lr.right - lr.left;
    const int dst_h = lr.bottom - lr.top;

    if (bmp && dst_w > 0 && dst_h > 0) {
        Gdiplus::Graphics g(dc);
        g.SetInterpolationMode(Gdiplus::InterpolationModeHighQualityBicubic);
        g.SetPixelOffsetMode(Gdiplus::PixelOffsetModeHalf);

        Gdiplus::ColorMatrix cm = {};
        cm.m[0][0] = cm.m[1][1] = cm.m[2][2] = 1.0f;
        cm.m[3][3] = logo_opacity;
        cm.m[4][4] = 1.0f;
        Gdiplus::ImageAttributes ia;
        ia.SetColorMatrix(&cm);

        Gdiplus::Rect dst(lr.left, lr.top, dst_w, dst_h);
        g.DrawImage(bmp, dst, 0, 0, (int)bmp->GetWidth(), (int)bmp->GetHeight(),
                    Gdiplus::UnitPixel, &ia);
    }   /* g flushes to the DC on scope exit, before the GDI text below */

    if (!show_label || text_opacity <= 0.0f) return;

    EnsureFonts();
    if (!label_font_) return;

    const int v = (int)(255.0f * text_opacity);
    SetBkMode(dc, TRANSPARENT);

    HFONT old = (HFONT)SelectObject(dc, label_font_);
    SetTextColor(dc, RGB(v, v, v));
    const int max_y = (int)height - kLabelFontPx - 8;
    int label_y = lr.bottom + (int)((float)dst_h * kLabelGapFrac);
    if (label_y > max_y) label_y = max_y;
    RECT r{ 0, label_y, (int)width, label_y + kLabelFontPx * 2 };
    DrawTextW(dc, label.c_str(), (int)label.size(), &r,
              DT_CENTER | DT_TOP | DT_SINGLELINE | DT_NOPREFIX);
    SelectObject(dc, old);
}

void BootScreen::DrawAnimation(HDC dc, uint32_t width, uint32_t height) {
    switch (phase_) {
        case Phase::CerfFadeIn:
        case Phase::CerfHold:
            DrawLogoFrame(dc, width, height, cur_op_, false, L"", 0.0f);
            break;
        case Phase::TextFadeIn:
        case Phase::TextHold:
            DrawLogoFrame(dc, width, height, 1.0f, true, CurrentLabelText(), cur_op_);
            break;
        case Phase::Finished:
            break;
    }
}

void BootScreen::DrawHeldFinal(HDC dc, uint32_t width, uint32_t height) {
    DrawLogoFrame(dc, width, height, 1.0f, true, CurrentLabelText(), 1.0f);
}

void BootScreen::DrawHwStatusLine(HDC dc, uint32_t width, uint32_t height) {
    hw_line_rect_ = RECT{};
    const std::string last = emu_.Get<HwScreen>().LastLine();
    if (last.empty()) return;

    EnsureFonts();
    if (!hw_line_font_) return;

    const float op = (phase_ == Phase::CerfFadeIn) ? cur_op_ : 1.0f;
    const int   dv = (int)(150.0f * op);

    const int bottom = (int)height - kBootBarPx - 4;
    RECT r{ kMargin, bottom - kHwLineHeightPx, (int)width - kMargin, bottom };

    const std::wstring wide = Utf8ToWide(last.c_str());
    HFONT old = (HFONT)SelectObject(dc, hw_line_font_);
    SetBkMode(dc, TRANSPARENT);
    SetTextColor(dc, RGB(dv, dv, dv));
    DrawTextW(dc, wide.c_str(), (int)wide.size(), &r,
              DT_CENTER | DT_VCENTER | DT_SINGLELINE | DT_END_ELLIPSIS | DT_NOPREFIX);
    SelectObject(dc, old);

    hw_line_rect_ = RECT{ 0, r.top - 2, (int)width, (int)height - kBootBarPx };
}

bool BootScreen::HitTestHwLine(int x, int y) const {
    return x >= hw_line_rect_.left && x < hw_line_rect_.right &&
           y >= hw_line_rect_.top  && y < hw_line_rect_.bottom;
}

void BootScreen::DrawWatermark(HDC dc, uint32_t width, uint32_t height) {
    DrawLogoFrame(dc, width, height, kDimOpacity, false, L"", 0.0f, true);
}

void BootScreen::Restart() {
    restart_req_.store(true, std::memory_order_release);
}
void BootScreen::SetRestartLabel(const wchar_t* static_text) {
    restart_label_.store(static_text, std::memory_order_release);
}
void BootScreen::OnFramebufferLatched() {
    restart_label_.store(nullptr, std::memory_order_release);
    fb_latched_req_.store(true);
}
