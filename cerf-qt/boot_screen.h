#pragma once

#include "dpi_scale.h"
#include "painter.h"

#include <cerfcore/core/service.h>

#include <atomic>
#include <cstdint>
#include <memory>
#include <string>

namespace cerffrontend {

class BootScreen : public cerfcore::Service {
public:
    using cerfcore::Service::Service;

    void OnReady() override;

    void RenderInto(uint32_t* dib_bgra32, uint32_t width, uint32_t height, int dpi);
    void DrawWatermark(Painter& p, uint32_t width, uint32_t height);

    bool Finished() const { return phase_ == Phase::Finished; }

    void Restart();
    void SetRestartLabel(const char* static_text);
    void OnFramebufferLatched();

    bool HitTestHwLine(int x, int y) const;

private:
    enum class Phase { CerfFadeIn, CerfHold, TextFadeIn, TextHold, Finished };
    enum class LabelMode { Starting, Restarting };

    int         S(int px) const;
    void        Advance(uint64_t now_ms);
    uint64_t    BgSignature(uint32_t width, uint32_t height);
    std::string CurrentLabelText() const;
    Font        LabelFont() const;
    int         HwLineTop(uint32_t height) const;
    int         ContentBottom(uint32_t height) const;
    Rect        LogoRect(uint32_t width, uint32_t height, float label_progress, bool native) const;
    float       GlowOpacity() const;
    void        DrawGlow(uint32_t* bits, uint32_t width, uint32_t height, const Rect& logo,
                         float opacity) const;
    void DrawLogoFrame(Painter& p, uint32_t width, uint32_t height, float logo_opacity,
                       bool show_label, const std::string& label, float text_opacity,
                       bool native_size = false);
    void DrawAnimation(Painter& p, uint32_t width, uint32_t height);
    void DrawHwStatusLine(Painter& p, uint32_t width, uint32_t height);

    std::string                       short_name_;
    std::unique_ptr<OffscreenSurface> bg_;
    uint64_t                          bg_sig_   = ~0ull;
    bool                              bg_valid_ = false;
    int                               dpi_      = kDefaultDpi;
    Rect                              hw_line_rect_;
    std::string                       hw_line_;
    int                               label_line_h_ = 0;

    Phase     phase_       = Phase::CerfFadeIn;
    uint64_t  phase_start_ = 0;
    bool      started_     = false;
    float     cur_op_      = 0.0f;
    LabelMode label_mode_  = LabelMode::Starting;
    bool      fb_latched_  = false;

    std::atomic<bool>        restart_req_{false};
    std::atomic<bool>        fb_latched_req_{false};
    std::atomic<const char*> restart_label_{nullptr};
};

}
