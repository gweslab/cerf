#pragma once

#include "../core/service.h"

#define NOMINMAX
#include <windows.h>

#include <atomic>
#include <cstdint>
#include <string>

namespace Gdiplus { class Bitmap; }

/* The Boot Screen tab: CERF logo fade animation + bottom CPU-activity bar.
   Advance() runs off the render loop's wall clock, never an internal timer: a
   separate timer would not freeze on pause and would keep ticking after the
   tab stops being rendered. */
class BootScreen : public Service {
public:
    using Service::Service;
    ~BootScreen() override;

    void OnReady() override;
    void OnShutdown() override;

    /* UI thread. Compose the Boot Screen tab into the host surface: advance the
       animation to the present clock, draw the current logo state, then the
       activity bar. */
    void RenderInto(HDC dc, uint32_t* dib_bgra32, uint32_t width, uint32_t height);

    /* UI thread. Draw the dimmed, native-size CERF logo centred on `dc` as a
       static watermark (no animation). The Hardware Screen tab draws it behind
       its text. */
    void DrawWatermark(HDC dc, uint32_t width, uint32_t height);

    bool Finished() const { return phase_ == Phase::Finished; }

    void Restart();

    void SetRestartLabel(const wchar_t* static_text);

    /* Any thread. The framebuffer tab has taken over; finish the animation and
       switch the held label to "Switched to LCD". */
    void OnFramebufferLatched();

    bool HitTestHwLine(int x, int y) const;

private:
    enum class Phase { CerfFadeIn, CerfHold, TextFadeIn, TextHold, Finished };
    enum class LabelMode { Starting, Restarting };

    void         Advance(uint64_t now_ms);
    void         RebuildBgDib(int w, int h);
    uint64_t     BgSignature(uint32_t width, uint32_t height);
    void         EnsureLogosLoaded();
    void         EnsureFonts();
    std::wstring CurrentLabelText() const;
    RECT         LogoRect(uint32_t width, uint32_t height,
                          float label_progress, bool native) const;
    float        GlowOpacity() const;
    void         DrawGlow(uint32_t* bits, uint32_t width, uint32_t height,
                          const RECT& logo, float opacity) const;
    void DrawLogoFrame(HDC dc, uint32_t width, uint32_t height,
                       float logo_opacity,
                       bool show_label, const std::wstring& label, float text_opacity,
                       bool cerf_native_size = false);
    void DrawAnimation(HDC dc, uint32_t width, uint32_t height);   /* live frame */
    void DrawHeldFinal(HDC dc, uint32_t width, uint32_t height);   /* finished */
    void DrawHwStatusLine(HDC dc, uint32_t width, uint32_t height);

    Gdiplus::Bitmap* cerf_logo_     = nullptr;
    bool             logos_loaded_  = false;
    std::wstring     short_name_;               /* board short name, widened */

    HDC       bg_dc_    = nullptr;
    HBITMAP   bg_dib_   = nullptr;
    uint32_t* bg_bits_  = nullptr;
    int       bg_w_     = 0;
    int       bg_h_     = 0;
    uint64_t  bg_sig_   = ~0ull;
    bool      bg_valid_ = false;

    HFONT label_font_      = nullptr;
    HFONT hw_line_font_    = nullptr;

    RECT hw_line_rect_{};

    /* State-machine fields - touched only by Advance/Draw* on the UI thread. */
    Phase     phase_        = Phase::CerfFadeIn;
    uint64_t  phase_start_  = 0;
    bool      started_      = false;
    float     cur_op_       = 0.0f;
    LabelMode label_mode_   = LabelMode::Starting;
    bool      fb_latched_   = false;

    /* Cross-thread requests, consumed at the top of Advance. */
    std::atomic<bool> restart_req_{false};
    std::atomic<bool> fb_latched_req_{false};
    std::atomic<const wchar_t*> restart_label_{nullptr};
};
